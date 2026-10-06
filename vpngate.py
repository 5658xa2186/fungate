from urllib.parse import quote, urlparse, parse_qsl, urlencode, urlunparse
from requests.adapters import HTTPAdapter
from threading import local

def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (gate-checker)"})
    ad = HTTPAdapter(pool_connections=CONCURRENCY, pool_maxsize=CONCURRENCY, max_retries=0)
    s.mount("http://", ad)
    s.mount("https://", ad)
    return s

_tls = local()

def _thread_session():
    s = getattr(_tls, "session", None)
    if s is None:
        s = _session()
        _tls.session = s
    return s

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = next(
        (i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")),
        None,
    )
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表頭行 (HostName)")
    header = [h.strip().lstrip("*") for h in lines[header_idx].lstrip("#").split(",")]
    reader = csv.reader(lines[header_idx + 1:])
    def col(*names, default=None):
        lower = [h.lower() for h in header]
        for n in names:
            if n in lower:
                return lower.index(n)
        return default
    i_host = col("hostname", default=0)
    i_ip = col("ip", default=1)
    i_cl = col("countrylong", default=5)
    i_cs = col("countryshort", default=6)
    i_b64 = col("openvpn_configdata_base64")
    if i_b64 is None:
        i_b64 = next((i for i, h in enumerate(header) if "base64" in h.lower()), len(header) - 1)
    rows = []
    for fields in reader:
        if len(fields) <= max(i_host, i_ip, i_cl, i_cs, i_b64):
            continue
        host, ip = fields[i_host].strip(), fields[i_ip].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host, "ip": ip,
            "country_long": fields[i_cl].strip(),
            "country_short": fields[i_cs].strip(),
            "config_b64": fields[i_b64].strip(),
        })
    return rows

def check_url(host, port):
    """Append host:port to WORKER_CHECK_URL without encoding ':' '.'."""
    target = f"{host}:{port}"
    base = WORKER_CHECK_URL
    if base.endswith("=") or base.endswith("@"):
        return base + quote(target, safe=":.")
    p = urlparse(base)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q["proxyip"] = target
    return urlunparse(p._replace(query=urlencode(q, safe=":.")))

def check_one(node):
    out = dict(node)
    out.update({
        "protocol": "sstp",
        "status": "failed",
        "success": False,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "exit": None,
        "residential": "unknown",
    })
    user = os.environ.get("SSTP_USER", "vpn")
    pw = os.environ.get("SSTP_PASS", "vpn")
    out["link"] = f"sstp://{user}:{pw}@{node['host']}:{node['port']}"
    try:
        r = _thread_session().get(check_url(node["host"], node["port"]), timeout=CHECK_TIMEOUT)
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = None if ok else (j.get("error") or j.get("message") or "check failed")
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes):
    results = [None] * len(nodes)
    done = 0
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        fmap = {pool.submit(check_one, n): i for i, n in enumerate(nodes)}
        for fut in as_completed(fmap):
            i = fmap[fut]
            results[i] = fut.result()
            done += 1
            if done == len(nodes) or done % 50 == 0:
                log("CLOUDFLARE WORKER", f"进度 {done}/{len(nodes)}")
    return results

def iter_grouped_nodes(data):
    items = sorted(
        data["countries"].items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in items:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code not in ("", "?") else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res = [n for n in nodes if n.get("residential") == "residential"]
        dc = [n for n in nodes if n.get("residential") != "residential"]
        yield zh, code, grp, res, dc
