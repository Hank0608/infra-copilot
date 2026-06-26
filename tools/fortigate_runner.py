"""FortiGate REST API client — read-only 查詢防火牆狀態。"""

import json
import os
import urllib.request
import urllib.parse
import ssl
from contextlib import contextmanager
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

FW_HOST = os.getenv("FW_HOST")
FW_USER = os.getenv("FW_USER")
FW_PASS = _secret("FW_PASS")

# 忽略自簽憑證
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _base_url() -> str:
    return f"https://{FW_HOST}"


def login() -> dict:
    """登入 FortiGate，回傳 {'cookie': str, 'csrf': str}。"""
    url  = f"{_base_url()}/logincheck"
    body = urllib.parse.urlencode({"username": FW_USER, "secretkey": FW_PASS, "ajax": "1"}).encode()
    req  = urllib.request.Request(url, data=body, method="POST")
    res  = urllib.request.urlopen(req, context=CTX, timeout=10)

    # 取 session cookie
    cookie = ""
    for header, value in res.getheaders():
        if header.lower() == "set-cookie":
            for part in value.split(";"):
                part = part.strip()
                if part.startswith("APSCOOKIE_") or part.startswith("ccsrftoken"):
                    cookie += part + "; "

    # 取 CSRF token（從 cookie 中的 ccsrftoken）
    csrf = ""
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("ccsrftoken="):
            csrf = part.split("=", 1)[1].strip('"')

    return {"cookie": cookie.strip(), "csrf": csrf}


def _get(path: str, session: dict, params: dict = None) -> dict:
    url = f"{_base_url()}/api/v2/{path.lstrip('/')}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Cookie", session["cookie"])
    if session.get("csrf"):
        req.add_header("X-CSRFTOKEN", session["csrf"])
    res = urllib.request.urlopen(req, context=CTX, timeout=15)
    return json.loads(res.read())


def logout(session: dict):
    url = f"{_base_url()}/logout"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Cookie", session["cookie"])
    try:
        urllib.request.urlopen(req, context=CTX, timeout=5)
    except Exception:
        pass


@contextmanager
def _session():
    """建立 FortiGate 連線，離開 with 區塊時自動 logout（含例外狀況）。"""
    sess = login()
    try:
        yield sess
    finally:
        logout(sess)


# ── 查詢函式 ──────────────────────────────────────────────

def get_system_status(session: dict) -> dict:
    return _get("monitor/system/status", session)


def get_interfaces(session: dict) -> list:
    r = _get("cmdb/system/interface", session, {"format": "name|ip|status|type|vdom"})
    return r.get("results", [])


def get_policies(session: dict, vdom: str = "root") -> list:
    r = _get("cmdb/firewall/policy", session, {"vdom": vdom})
    return r.get("results", [])


def get_vips(session: dict, vdom: str = "root") -> list:
    """Virtual IPs (DNAT / port forward)。"""
    r = _get("cmdb/firewall/vip", session, {"vdom": vdom})
    return r.get("results", [])


def get_static_routes(session: dict, vdom: str = "root") -> list:
    r = _get("cmdb/router/static", session, {"vdom": vdom})
    return r.get("results", [])


def get_active_sessions(session: dict, vdom: str = "root") -> dict:
    return _get("monitor/firewall/session", session, {"vdom": vdom, "count": 50})


def address_lookup(session: dict, ip: str) -> dict:
    """
    找出 FortiGate 中包含指定 IP 的所有 address objects 與 groups（含遞迴展開）。
    回傳 {"ip", "objects": [...], "groups": [...]}
    """
    import ipaddress
    target = ipaddress.ip_address(ip)

    addr_r = _get("cmdb/firewall/address", session,
                  {"format": "name|subnet|type|start-ip|end-ip"})
    ag_r   = _get("cmdb/firewall/addrgrp", session, {"format": "name|member"})

    # Step 1: address objects 直接包含此 IP（排除 0.0.0.0/0 catch-all）
    matched_obj = []
    for a in addr_r.get("results", []):
        t = a.get("type", "")
        try:
            if t == "ipmask":
                parts = a.get("subnet", "").split()
                if len(parts) == 2:
                    if parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        continue  # skip catch-all (all, FABRIC_DEVICE, etc.)
                    net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                    if target in net:
                        matched_obj.append(a["name"])
            elif t == "iprange":
                s = ipaddress.ip_address(a.get("start-ip", "0.0.0.0"))
                e = ipaddress.ip_address(a.get("end-ip", "0.0.0.0"))
                if s <= target <= e:
                    matched_obj.append(a["name"])
        except Exception:
            pass

    # Step 2: 往上遞迴找所有包含這些 object 的 group
    grp_map = {g["name"]: {m["name"] for m in g.get("member", [])}
               for g in ag_r.get("results", [])}

    def _parents(name: str, visited: set) -> list:
        out = []
        for grp, members in grp_map.items():
            if grp not in visited and name in members:
                visited.add(grp)
                out.append(grp)
                out.extend(_parents(grp, visited))
        return out

    matched_grp, seen = [], set()
    for obj in matched_obj:
        for g in _parents(obj, seen):
            if g not in matched_grp:
                matched_grp.append(g)

    return {"ip": ip, "objects": matched_obj, "groups": matched_grp}


def _interface_for_ip(session: dict, ip: str) -> str:
    """找出 IP 所屬的 FortiGate interface 名稱（依 subnet 比對，跳過 0.0.0.0）。"""
    import ipaddress
    target = ipaddress.ip_address(ip)
    for iface in get_interfaces(session):
        ip_str = iface.get("ip", "")
        if not ip_str:
            continue
        try:
            parts = ip_str.split()
            if parts[0] == "0.0.0.0":
                continue
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            if target in net and target != ipaddress.ip_address(parts[0]):
                return iface.get("name", "")
        except Exception:
            pass
    return ""


def policy_check(session: dict, src_ip: str, dst_ip: str, vdom: str = "root") -> dict:
    """
    模擬 FortiGate top-down policy 查找：src_ip → dst_ip。
    自動偵測 srcintf，過濾掉來自其他 interface 的 policy。
    回傳第一條命中的 policy 及 action（accept / deny / no_policy）。
    """
    src_info  = address_lookup(session, src_ip)
    dst_info  = address_lookup(session, dst_ip)
    src_intf  = _interface_for_ip(session, src_ip)

    src_names = set(src_info["objects"] + src_info["groups"])
    dst_names = set(dst_info["objects"] + dst_info["groups"])

    first_match = None
    for p in get_policies(session, vdom):   # API 回傳順序即評估順序
        if p.get("status") != "enable":
            continue
        # srcintf 過濾：若偵測到來源 interface，只看 srcintf 包含它的 policy
        if src_intf:
            p_srcintf = {x.get("name", "") for x in p.get("srcintf", [])}
            if "any" not in p_srcintf and src_intf not in p_srcintf:
                continue
        p_srcs = {x.get("name", "") for x in p.get("srcaddr", [])}
        p_dsts = {x.get("name", "") for x in p.get("dstaddr", [])}
        src_hit = "all" in p_srcs or bool(p_srcs & src_names)
        dst_hit = "all" in p_dsts or bool(p_dsts & dst_names)
        if src_hit and dst_hit:
            first_match = {
                "policyid":    p.get("policyid"),
                "name":        p.get("name", ""),
                "action":      p.get("action"),
                "srcintf":     [x.get("name") for x in p.get("srcintf", [])],
                "dstintf":     [x.get("name") for x in p.get("dstintf", [])],
                "matched_src": sorted(p_srcs & src_names - {"all"}),
                "matched_dst": sorted(p_dsts & dst_names - {"all"}),
            }
            break

    return {
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_objects": src_info["objects"],
        "src_groups":  src_info["groups"],
        "dst_objects": dst_info["objects"],
        "dst_groups":  dst_info["groups"],
        "action":      first_match["action"] if first_match else "no_policy",
        "first_match": first_match,
    }


def find_vip_by_ip(session: dict, public_ip: str, vdom: str = "root") -> list:
    """找出對應某個公網 IP 的 VIP 規則。"""
    vips = get_vips(session, vdom)
    return [v for v in vips if public_ip in v.get("extip", "")]


def find_policy_by_dst(session: dict, dst_ip: str, vdom: str = "root") -> list:
    """找出目的地包含某 IP 的 policy。"""
    policies = get_policies(session, vdom)
    matched = []
    for p in policies:
        dsts = [d.get("name", "") for d in p.get("dstaddr", [])]
        if any(dst_ip in d for d in dsts) or dst_ip in str(p.get("dstaddr", "")):
            matched.append(p)
    return matched


def get_session_config(session: dict) -> dict:
    """查詢 FortiGate TCP session timeout 設定。

    回傳:
      session_ttl_default: int  — 預設 TCP idle session TTL（秒）
      session_ttl_ports:   list — 個別 port 的 TTL override
      admintimeout:        int  — 管理介面閒置登出（分鐘）
    """
    ttl_r  = _get("cmdb/system/session-ttl", session).get("results", {})
    glob_r = _get("cmdb/system/global", session).get("results", {})
    return {
        "session_ttl_default": int(ttl_r.get("default", 3600)),
        "session_ttl_ports":   ttl_r.get("port", []),
        "admintimeout":        int(glob_r.get("admintimeout", 0)),
    }


# ── 日報資料收集 ──────────────────────────────────────────

def get_report_data() -> dict:
    """收集日報所需資料：HA 狀態、Firmware、IPsec VPN 隧道。"""
    with _session() as sess:
        # HA（順便取 CPU/MEM/uptime）
        ha_raw = _get("monitor/system/ha-statistics", sess).get("results", [])
        ha = []
        for m in ha_raw:
            role = "primary" if "primary" in m.get("hostname", "").lower() else "secondary"
            ha.append({
                "hostname":    m.get("hostname", ""),
                "role":        role,
                "cpu":         m.get("cpu_usage", 0),
                "mem":         m.get("mem_usage", 0),
                "sessions":    m.get("sessions", 0),
                "uptime_days": m.get("uptime", 0) // 86400,
            })

        # Firmware
        fw_raw   = _get("monitor/system/firmware", sess).get("results", {})
        cur      = fw_raw.get("current", {})
        avail    = [a.get("version", "") for a in fw_raw.get("available", []) if a.get("version")]
        firmware = {"current": cur.get("version", ""), "available": avail}

        # IPsec VPN
        vpn_raw = _get("monitor/vpn/ipsec", sess).get("results", [])
        tunnels = []
        for t in vpn_raw:
            statuses = [p.get("status") for p in t.get("proxyid", [])]
            up = bool(statuses) and all(s == "up" for s in statuses)
            tunnels.append({
                "name":   t.get("name", ""),
                "up":     up,
                "rx_gb":  round(t.get("incoming_bytes", 0) / 1e9, 1),
                "tx_gb":  round(t.get("outgoing_bytes", 0) / 1e9, 1),
            })

        primary = next((m for m in ha if m["role"] == "primary"), ha[0] if ha else {})
        return {
            "ha":          ha,
            "firmware":    firmware,
            "tunnels":     tunnels,
            "cpu":         primary.get("cpu", 0),
            "mem":         primary.get("mem", 0),
            "sessions":    primary.get("sessions", 0),
            "uptime_days": primary.get("uptime_days", 0),
        }


# ── 每日報告 ──────────────────────────────────────────────

def daily_report() -> str:
    with _session() as sess:
        status = get_system_status(sess)
        ifaces = get_interfaces(sess)
        vips   = get_vips(sess)

    lines = ["=" * 55, "  FortiGate 狀態報告", "=" * 55]

    # 系統資訊
    r = status.get("results", {})
    lines.append(f"\n【系統資訊】")
    lines.append(f"  Hostname : {r.get('hostname', 'N/A')}")
    lines.append(f"  版本     : {r.get('version', 'N/A')}")
    lines.append(f"  Uptime   : {r.get('uptime', 'N/A')} 秒")

    # 介面狀態
    lines.append(f"\n【介面狀態】")
    for iface in ifaces:
        status_str = "✅ up" if iface.get("status") == "up" else "❌ down"
        ip = iface.get("ip", "").replace(" ", "/")
        lines.append(f"  {status_str}  {iface.get('name',''):<20} {ip}")

    # VIP 清單
    lines.append(f"\n【VIP / Port Forward】共 {len(vips)} 筆")
    for v in vips[:20]:
        ext  = v.get("extip", "")
        ext_port = v.get("extintf", "")
        map_ip   = v.get("mappedip", [{}])
        mapped   = map_ip[0].get("range", "") if map_ip else ""
        lines.append(f"  {v.get('name',''):<30} {ext} → {mapped}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"

    if cmd == "report":
        print(daily_report())

    elif cmd == "lookup":
        ip = sys.argv[2] if len(sys.argv) > 2 else ""
        if not ip:
            print("Usage: fortigate_runner.py lookup <ip>")
        else:
            with _session() as sess:
                r = address_lookup(sess, ip)
            print(f"IP: {r['ip']}")
            print(f"Objects : {r['objects']}")
            print(f"Groups  : {r['groups']}")

    elif cmd == "check":
        src = sys.argv[2] if len(sys.argv) > 2 else ""
        dst = sys.argv[3] if len(sys.argv) > 3 else ""
        if not src or not dst:
            print("Usage: fortigate_runner.py check <src_ip> <dst_ip>")
        else:
            with _session() as sess:
                r = policy_check(sess, src, dst)
            action_icon = "✅" if r["action"] == "accept" else ("❌" if r["action"] == "deny" else "⬜")
            print(f"{action_icon} {src} → {dst}  action={r['action']}")
            print(f"   src: objects={r['src_objects']}  groups={r['src_groups']}")
            print(f"   dst: objects={r['dst_objects']}  groups={r['dst_groups']}")
            if r["first_match"]:
                m = r["first_match"]
                print(f"   policy [{m['policyid']}] \"{m['name']}\"  {m['srcintf']} → {m['dstintf']}")
                print(f"   matched src={m['matched_src']}  dst={m['matched_dst']}")
            else:
                print("   (no matching policy — implicit deny)")

    elif cmd == "session-config":
        with _session() as sess:
            r = get_session_config(sess)
        ttl = r["session_ttl_default"]
        print(f"TCP session idle TTL : {ttl} 秒 ({ttl // 60} 分鐘)")
        print(f"管理介面 timeout     : {r['admintimeout']} 分鐘")
        if r["session_ttl_ports"]:
            print(f"Per-port TTL override: {r['session_ttl_ports']}")

    else:
        print("Usage: fortigate_runner.py [report|lookup <ip>|check <src_ip> <dst_ip>|session-config]")
