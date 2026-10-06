#!/usr/bin/env python3
"""
VPN Gate SSTP 節點檢測流水線 (優化版)
=====================================
流程:
  1. 取得 VPN Gate 原始節點 (官方 API CSV, 失敗回退 GitHub 鏡像)
  2. 篩選帶 TCP 入口的中繼 = SSTP 可用節點
  3. 按 host+port+protocol 去重
  4. 併發呼叫 Cloudflare Worker 檢測
  5. 生成 public/data.json + index.html + chains.txt + hosts.txt + sub.txt
  6. GitHub Pages 部署

退出碼:
  0 = 正常完成
  1 = 硬性失敗
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# 控制台編碼保護
# ---------------------------------------------------------------------------
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (集中定義, 均可用環境變數覆蓋)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get(
    "CHECK_WORKER", "https://autumn-0800092.superxa2186.workers.dev/check?sstp=vpn:vpn@"
)
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
CHECK_RETRIES = int(os.environ.get("CHECK_RETRIES", "2"))        # 新增: 單節點重試次數
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# edgetunnel 配置 (提前定義, 修復原版引用順序問題)
EDT_UUID = os.environ.get("EDT_UUID", "90c14586-42a5-4c30-959d-8b36608d67f7")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "ed.xiaolei.qzz.io")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")

CHAIN_URL = os.environ.get("CHAIN_URL", "https://jerylihub.github.io/gate/chains.txt")
HOSTS_URL = os.environ.get("HOSTS_URL", "https://jerylihub.github.io/gate/hosts.txt")
SUB_URL = os.environ.get("SUB_URL", "https://jerylihub.github.io/gate/sub.txt")

EDGE_HOSTS: List[str] = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "104.21.80.52:443,104.18.48.164:443,104.21.23.166:443,auto.dolby.dpdns.org:443,"
        "cdn.cnno.de:443,104.21.34.127:443,104.19.71.239:443",
    ).split(",")
    if h.strip()
]

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH: Dict[str, str] = {
    "JP": "日本", "KR": "韓國", "US": "美國", "CA": "加拿大", "RU": "俄羅斯",
    "RO": "羅馬尼亞", "TH": "泰國", "VN": "越南", "DE": "德國", "FR": "法國",
    "GB": "英國", "UK": "英國", "SG": "新加坡", "TW": "台灣", "HK": "香港",
    "CN": "中國", "AU": "澳大利亞", "NL": "荷蘭", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波蘭", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亞", "MY": "馬來西亞", "PH": "菲律賓",
    "TR": "土耳其", "UA": "烏克蘭", "CZ": "捷克", "GR": "希臘", "PT": "葡萄牙",
    "FI": "芬蘭", "NO": "挪威", "DK": "丹麥", "IE": "愛爾蘭", "BE": "比利時",
    "AT": "奧地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥倫比亞",
    "NZ": "新西蘭", "ZA": "南非", "IL": "以色列", "AE": "阿聯酋", "SA": "沙特",
    "EG": "埃及", "HR": "克羅地亞", "BY": "白俄羅斯", "GD": "格林納達",
    "LV": "拉脫維亞", "EE": "愛沙尼亞", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亞", "BG": "保加利亞", "RS": "塞爾維亞", "GE": "格魯吉亞",
    "MD": "摩爾多瓦", "AM": "亞美尼亞", "KZ": "哈薩克斯坦", "UZ": "烏茲別克斯坦",
    "MN": "蒙古", "NP": "尼泊爾", "LK": "斯里蘭卡", "MM": "緬甸",
}

# ---------------------------------------------------------------------------
# 日誌
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()
_section: Optional[str] = None


def log(section: str, msg: str = "") -> None:
    global _section
    with _log_lock:
        if section != _section:
            print(f"========== {section} ==========")
            _section = section
        if msg:
            print(msg, flush=True)


def die(msg: str) -> None:
    log("FATAL", f"[失敗] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 優雅關閉
# ---------------------------------------------------------------------------
_shutdown = threading.Event()


def _signal_handler(signum: int, _frame: Any) -> None:
    log("SIGNAL", f"收到信號 {signum}, 正在優雅關閉…")
    _shutdown.set()


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# HTTP Session 工廠 (連線池 + 自動重試)
# ---------------------------------------------------------------------------
def make_session(pool_size: int = CONCURRENCY) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=CHECK_RETRIES,
        backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers["User-Agent"] = "Mozilla/5.0 (compatible; gate-checker)"
    return s


# ---------------------------------------------------------------------------
# 節點資料結構
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Node:
    host: str
    port: int
    ip: str
    country: str
    country_code: str


@dataclass
class CheckResult:
    node: Node
    protocol: str = "sstp"
    link: str = ""
    status: str = "failed"
    success: bool = False
    checked_at: str = ""
    latency_ms: Optional[float] = None
    colo: Optional[str] = None
    error: Optional[str] = None
    worker_error: bool = False
    exit: Optional[Dict[str, Any]] = None
    residential: str = "unknown"


# ---------------------------------------------------------------------------
# 第 1 步: 取得 VPN Gate 原始節點
# ---------------------------------------------------------------------------
def fetch_vpngate(session: requests.Session) -> Tuple[List[Dict[str, str]], str]:
    # 主源: 官方 CSV
    try:
        log("VPN GATE", f"取得官方 API: {VPNGATE_API}")
        resp = session.get(VPNGATE_API, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 取得 {len(rows)} 個原始節點")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 回傳 0 行資料")
    except Exception as exc:
        log("VPN GATE", f"官方 API 取得失敗: {exc}")

    # 回退源: GitHub 鏡像
    try:
        log("VPN GATE", f"回退鏡像: {VPNGATE_MIRROR}")
        resp = session.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(鏡像) 取得 {len(rows)} 個原始節點")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退鏡像也失敗: {exc}")

    die("VPN Gate 官方 API 與回退鏡像均不可用, 資料源完全失敗")
    return [], ""  # unreachable, 讓型別檢查器滿意


def parse_csv(text: str) -> List[Dict[str, str]]:
    """解析官方 CSV, 用 DictReader 自動對應欄位名。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表頭行 (HostName)")

    # 去掉行首 # 後用 DictReader
    header_line = lines[header_idx].lstrip("#")
    data_text = "\n".join([header_line] + lines[header_idx + 1:])
    reader = csv.DictReader(io.StringIO(data_text))

    # 建立欄位名映射 (大小寫 / 星號容錯)
    field_map: Dict[str, str] = {}
    if reader.fieldnames:
        for col in reader.fieldnames:
            key = col.strip().lstrip("*").lower()
            field_map[key] = col

    def get(row: Dict[str, Any], *names: str) -> str:
        for n in names:
            orig = field_map.get(n)
            if orig and orig in row and row[orig] is not None:
                return str(row[orig]).strip()
        return ""

    rows: List[Dict[str, str]] = []
    for row in reader:
        host = get(row, "hostname")
        ip = get(row, "ip")
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": get(row, "countrylong"),
            "country_short": get(row, "countryshort"),
            "config_b64": get(row, "openvpn_configdata_base64", "openvpn_configdata"),
        })
    return rows


def parse_mirror_json(data: Any) -> List[Dict[str, str]]:
    servers: List[Dict[str, Any]] = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)

    rows: List[Dict[str, str]] = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(
                s.get("countrylong") or s.get("country_long") or s.get("country") or ""
            ).strip(),
            "country_short": str(
                s.get("countryshort") or s.get("country_short") or ""
            ).strip(),
            "config_b64": str(
                s.get("openvpn_configdata_base64") or s.get("config_b64") or ""
            ).strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 篩選 SSTP 節點
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows: List[Dict[str, str]]) -> List[Node]:
    nodes: List[Node] = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode(
                    "utf-8", "replace"
                )
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not 1 <= port <= 65535:
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append(Node(
            host=host,
            port=port,
            ip=r["ip"],
            country=r["country_long"],
            country_code=r["country_short"],
        ))
    return nodes


def dedupe(nodes: List[Node]) -> List[Node]:
    seen: set[Tuple[str, int, str]] = set()
    out: List[Node] = []
    for n in nodes:
        key = (n.host.lower(), n.port, "sstp")
        if key not in seen:
            seen.add(key)
            out.append(n)
    return out


# ---------------------------------------------------------------------------
# 第 3 步: 併發檢測
# ---------------------------------------------------------------------------
def classify_network(
    host: str, exit_org: Optional[str], is_datacenter: Optional[bool]
) -> str:
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def check_one(node: Node, session: requests.Session) -> Dict[str, Any]:
    url = WORKER_CHECK_URL + quote(f"{node.host}:{node.port}", safe="")
    out: Dict[str, Any] = {
        "host": node.host,
        "port": node.port,
        "ip": node.ip,
        "country": node.country,
        "country_code": node.country_code,
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{node.host}:{node.port}",
        "status": "failed",
        "success": False,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "latency_ms": None,
        "colo": None,
        "error": None,
        "worker_error": False,
        "exit": None,
        "residential": "unknown",
    }
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT)
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
            out["residential"] = classify_network(
                node.host, org, exit_info.get("is_datacenter")
            )
        else:
            out["residential"] = classify_network(node.host, None, None)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
    return out


def check_all(nodes: List[Node], session: requests.Session) -> List[Dict[str, Any]]:
    total = len(nodes)
    done_count = 0
    results: List[Dict[str, Any]] = []
    report_step = max(1, total // 20)  # 每 5% 印出一次進度

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {pool.submit(check_one, n, session): n for n in nodes}
        for fut in as_completed(futures):
            if _shutdown.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            results.append(fut.result())
            done_count += 1
            if done_count % report_step == 0 or done_count == total:
                pct = done_count * 100 // total
                ok_so_far = sum(1 for r in results if r.get("success"))
                log("PROGRESS", f"  {done_count}/{total} ({pct}%)  可用 {ok_so_far}")
    return results


# ---------------------------------------------------------------------------
# 第 4 步: 生成輸出
# ---------------------------------------------------------------------------
def build_outputs(
    results: List[Dict[str, Any]],
    raw_count: int,
    sstp_count: int,
    source: str,
) -> Dict[str, Any]:
    available = [r for r in results if r.get("success")]
    countries: Dict[str, Dict[str, Any]] = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})[
            "nodes"
        ].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }

    by_country: Dict[str, Dict[str, Any]] = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(
            1 for n in grp["nodes"] if n["residential"] == "residential"
        )
        grp["datacenter"] = sum(
            1 for n in grp["nodes"] if n["residential"] == "datacenter"
        )
        grp["nodes"].sort(
            key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"])
        )
        by_country[name] = grp

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }


def _sorted_countries(countries: Dict[str, Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    return sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )


def _sorted_nodes(grp: Dict[str, Any]) -> List[Dict[str, Any]]:
    return sorted(
        grp["nodes"],
        key=lambda n: (
            0 if n.get("residential") == "residential" else 1,
            n.get("latency_ms") is None,
            n.get("latency_ms") or 0,
            n.get("host") or "",
        ),
    )


def build_chains_text(data: Dict[str, Any]) -> str:
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 節點 -> edgetunnel 鏈式代理清單",
        f"# 自動更新: {data['generated_at']} (每 30 分鐘重新檢測)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 節點備註裡直接貼上下面任意一行 (名字與指令連寫)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不變, 只有 $sstp:// 後面的地址每 30 分鐘自動更換",
        "# 帳號密碼固定 vpn:vpn ; 端口必須保留",
        "# ========================================================",
    ]
    for cname, grp in _sorted_countries(countries):
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code != "?" else cname)
        nodes = _sorted_nodes(grp)
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 節點 "
            f"(住宅 {grp['residential']} / 機房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-機房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def build_hosts_text(data: Dict[str, Any]) -> str:
    countries = data["countries"]
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = (
        [e.strip() for e in _entry.split(",") if e.strip()]
        or EDGE_HOSTS
        or [f"{EDT_DOMAIN}:443"]
    )
    lines = [
        "# edgetunnel「自定義優選IP」清單 (整段複製, 追加到後台現有內容後面)",
        f"# 自動更新: {data['generated_at']} (每 30 分鐘重新檢測)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@節點:端口",
        "# 入口用實測可用優選域名循環分配",
        "# 名字 = 國家-住宅/機房-編號, 直接區分住宅與機房",
        "# 名字固定; 只有 $sstp:// 後面的節點地址每 30 分鐘自動更換",
        "# 帳號密碼固定 vpn:vpn ; 節點端口必須保留",
        "# ========================================================",
    ]
    idx = 0
    for cname, grp in _sorted_countries(countries):
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code != "?" else cname)
        nodes = _sorted_nodes(grp)
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 節點 "
            f"(住宅 {grp['residential']} / 機房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-機房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def _b64_secret_encode(plaintext: str, secret: str) -> str:
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address: str, default_port: int = 80) -> Dict[str, Any]:
    address = re.sub(
        r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I
    ).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data: Dict[str, Any]) -> str:
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整訂閱 (vless://) —— 填進後台「訂閱連結」URL",
        f"# 自動更新: {data['generated_at']} (每 30 分鐘重新檢測)",
        f"# 固定地址: {SUB_URL}",
        f"# 節點域名: {EDT_DOMAIN} (傳輸 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 鏈式代理(編碼在 path)每 30 分鐘自動更換",
        "# 帳號密碼固定 vpn:vpn ; 節點端口已編碼進 path",
        "# ========================================================",
    ]
    for cname, grp in _sorted_countries(countries):
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code != "?" else cname)
        nodes = _sorted_nodes(grp)
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {
                "type": "sstp",
                **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443),
            }
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data: Dict[str, Any]) -> Tuple[str, ...]:
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 節點</title></head>"
            "<body><h1>VPN Gate SSTP 節點</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json())"
            ".then(d=>out.textContent=JSON.stringify(d.stats))"
            ".catch(e=>out.textContent='載入失敗:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))

    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# 配置校驗
# ---------------------------------------------------------------------------
def validate_config() -> None:
    if not WORKER_CHECK_URL:
        die("CHECK_WORKER 環境變數為空, 無法執行檢測")
    if CONCURRENCY < 1:
        die("CHECK_CONCURRENCY 必須 >= 1")
    if CHECK_TIMEOUT <= 0:
        die("CHECK_TIMEOUT 必須 > 0")
    if HTTP_TIMEOUT <= 0:
        die("HTTP_TIMEOUT 必須 > 0")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    validate_config()
    session = make_session()

    # 1) 資料源
    rows, source = fetch_vpngate(session)
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 回傳 0 個原始節點")

    # 2) SSTP 篩選 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"從 {raw_count} 個原始節點中沒有解析出任何 SSTP(TCP) 節點")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"原始節點: {raw_count}  SSTP: {sstp_count}  去重後: {len(uniq)}")

    # 3) 併發檢測
    log(
        "CLOUDFLARE WORKER",
        f"提交檢測: {len(uniq)} (併發 {CONCURRENCY}, 超時 {CHECK_TIMEOUT}s, 重試 {CHECK_RETRIES})",
    )
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"檢測成功: {len(success)}")
    log(
        "CLOUDFLARE WORKER",
        f"檢測失敗: {len(failed)}"
        + (f" (其中 Worker 異常 {len(worker_errors)})" if worker_errors else ""),
    )
    log("CLOUDFLARE WORKER", f"耗時: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部請求異常, 檢測服務不可用")

    # 4) 結果 + 輸出
    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用節點: {len(success)}  國家數量: {data['stats']['countries']}")

    paths = write_outputs(data)
    for p in paths:
        log("WEBSITE", f"生成 {os.path.relpath(p, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 執行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        die("使用者中斷")
    except Exception as exc:
        die(f"程式異常: {type(exc).__name__}: {exc}")
