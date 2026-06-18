"""內部 DNS 查詢工具 — 使用 dnspython 直打 AD DNS (10.11.1.121)。"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:
    raise ImportError("請先安裝 dnspython：pip3 install dnspython")

DNS_SERVER = os.getenv("DNS_SERVER", "10.11.1.121")
DNS_DOMAIN = os.getenv("AD_DOMAIN", "uti.com")

_DEFAULT_ZONES = ["ubiqconn.com", "uti.com"]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [DNS_SERVER]
    r.timeout     = 5
    r.lifetime    = 10
    return r


# ── 1. 正向解析 ───────────────────────────────────────────────

def resolve(hostname: str, record_type: str = "A") -> list[str]:
    """
    查詢任意主機名稱。hostname 可含或不含 domain。
    record_type: A / AAAA / CNAME / MX / TXT / NS / SRV
    回傳字串 list，查無或失敗回傳 []。
    """
    r = _resolver()
    try:
        ans = r.resolve(hostname, record_type)
        return [str(rr) for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


# ── 2. 反向解析 ───────────────────────────────────────────────

def reverse(ip: str) -> str:
    """PTR 查詢，回傳主機名稱（不含結尾 '.'），查無回傳 ''。"""
    r = _resolver()
    try:
        rev = dns.reversename.from_address(ip)
        ans = r.resolve(rev, "PTR")
        return str(ans[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return ""


# ── 3. 批次驗證 inventory 主機 ────────────────────────────────

def check_inventory(zones: list[str] = None) -> list[dict]:
    """
    讀取 inventory.yaml，對每個有 IP 的 node 做正向+反向解析比對。
    回傳 list of {label, ip, forward_names, reverse_name, mismatch}
    mismatch: IP → PTR 名稱與 inventory label 對不上
    """
    import yaml
    zones = zones or _DEFAULT_ZONES

    inv_path = ROOT / "inventory.yaml"
    with open(inv_path) as f:
        inv = yaml.safe_load(f)

    nodes = inv.get("nodes", {})
    results = []
    for label, node in nodes.items():
        ip = node.get("ip")
        if not ip:
            continue

        # 正向：試各 zone
        fwd = []
        for zone in zones:
            fwd += resolve(f"{label}.{zone}", "A")

        # 反向
        ptr = reverse(ip)

        results.append({
            "label":         label,
            "ip":            ip,
            "forward_ips":   fwd,
            "reverse_name":  ptr,
            "ip_in_fwd":     ip in fwd,
            "mismatch":      ptr and label.lower() not in ptr.lower(),
        })

    return results


# ── 4. MX 查詢 ────────────────────────────────────────────────

def get_mx(domain: str = "ubiqconn.com") -> list[dict]:
    """回傳 MX 記錄 [{priority, host}]，依 priority 排序。"""
    r = _resolver()
    try:
        ans = r.resolve(domain, "MX")
        result = [{"priority": rr.preference, "host": str(rr.exchange).rstrip(".")} for rr in ans]
        return sorted(result, key=lambda x: x["priority"])
    except dns.exception.DNSException:
        return []


# ── 5. 批次 A 查詢 ────────────────────────────────────────────

def bulk_resolve(hostnames: list[str], record_type: str = "A") -> dict[str, list[str]]:
    """一次查多筆，回傳 {hostname: [result, ...]}。"""
    return {h: resolve(h, record_type) for h in hostnames}


# ── 6. 一鍵健康檢查 ───────────────────────────────────────────

def health_check() -> str:
    """
    驗證 inventory 所有節點的 DNS 解析是否一致。
    列出：PTR 對不上 / 無 PTR / 正向查不到 的主機。
    """
    results = check_inventory()
    lines = ["=" * 55, "  DNS 健康檢查", "=" * 55]

    no_ptr   = [r for r in results if not r["reverse_name"]]
    mismatch = [r for r in results if r["mismatch"]]
    no_fwd   = [r for r in results if not r["ip_in_fwd"]]

    if mismatch:
        lines.append(f"\n🔴 PTR 名稱不符 ({len(mismatch)} 筆)")
        for r in mismatch:
            lines.append(f"  {r['label']:<20} {r['ip']:<16} PTR→{r['reverse_name']}")

    if no_ptr:
        lines.append(f"\n🟠 無 PTR 記錄 ({len(no_ptr)} 筆)")
        for r in no_ptr:
            lines.append(f"  {r['label']:<20} {r['ip']}")

    if no_fwd:
        lines.append(f"\n🟡 正向查無此 IP ({len(no_fwd)} 筆)")
        for r in no_fwd:
            lines.append(f"  {r['label']:<20} {r['ip']}")

    if not mismatch and not no_ptr and not no_fwd:
        lines.append("\n✅ 所有節點 DNS 正反解一致")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "health"

    if cmd == "resolve":
        name  = sys.argv[2] if len(sys.argv) > 2 else "ppdm.ubiqconn.com"
        rtype = sys.argv[3].upper() if len(sys.argv) > 3 else "A"
        result = resolve(name, rtype)
        print(f"{name} ({rtype}): {result or '查無結果'}")

    elif cmd == "reverse":
        ip  = sys.argv[2] if len(sys.argv) > 2 else "10.11.1.32"
        ptr = reverse(ip)
        print(f"{ip} -> {ptr or '查無 PTR'}")

    elif cmd == "mx":
        domain = sys.argv[2] if len(sys.argv) > 2 else "ubiqconn.com"
        for mx in get_mx(domain):
            print(f"  {mx['priority']:3d}  {mx['host']}")

    elif cmd == "inventory":
        for r in check_inventory():
            ptr_icon = "✅" if (r["reverse_name"] and not r["mismatch"]) else ("🔴" if r["mismatch"] else "🟠")
            fwd_icon = "✅" if r["ip_in_fwd"] else "🟡"
            print(f"{ptr_icon}{fwd_icon} {r['label']:<20} {r['ip']:<16} "
                  f"PTR={r['reverse_name'] or '—'}")

    elif cmd == "health":
        print(health_check())

    else:
        print("Usage: dns_runner.py [health | resolve <name> [type] | reverse <ip> | mx [domain] | inventory]")
        sys.exit(1)
