"""Linux 主機標準健診 — 透過 AD Session SSH 執行，回傳結構化報告。"""

from tools.ssh_runner import run_on_ip


CHECKS = {
    "os_uptime": "uname -r && uptime",
    "cpu_load":  "cat /proc/loadavg && nproc",
    "memory":    "free -h",
    "disk":      "df -h --output=source,size,used,avail,pcent,target | grep -Ev 'tmpfs|udev|Filesystem'",

    # Top 10 by CPU, then by MEM
    "top_cpu":   "ps aux --sort=-%cpu | head -11",
    "top_mem":   "ps aux --sort=-%mem | head -6",

    # Zombie: count + parent PID 分布
    "zombies": (
        "echo 'count:' && ps aux | awk '$8==\"Z\"' | wc -l && "
        "echo 'parents (count ppid user cmd):' && "
        "ps -eo pid,ppid,stat,user,comm | awk '$3~/^Z/{print $2}' "
        "| sort | uniq -c | sort -rn | head -10 "
        "| while read cnt ppid; do "
        "  info=$(ps -o user=,comm= -p $ppid 2>/dev/null || echo '? ?'); "
        "  echo \"  $cnt $ppid $info\"; "
        "done"
    ),

    # Swap per-process top 8
    "swap_consumers": (
        "for f in /proc/*/status; do "
        "  pid=${f%/status}; pid=${pid#/proc/}; "
        "  swap=$(awk '/VmSwap/{print $2}' $f 2>/dev/null); "
        "  [ -z \"$swap\" ] || [ \"$swap\" -eq 0 ] 2>/dev/null && continue; "
        "  cmd=$(cat /proc/$pid/comm 2>/dev/null || echo '?'); "
        "  echo \"$swap $pid $cmd\"; "
        "done | sort -rn | head -8 | awk '{printf \"%s MB\\t%s\\t%s\\n\", int($1/1024), $2, $3}'"
    ),

    # OOM killer 最近 10 筆
    "oom_log": (
        "journalctl -k --no-pager -n 100 2>/dev/null "
        "| grep -i 'oom\\|killed process\\|out of memory' | tail -10 "
        "|| dmesg 2>/dev/null | grep -i 'oom\\|killed process' | tail -10"
    ),

    # Docker (若 infra.ro 無 docker 群組則顯示 NO_ACCESS)
    "docker": (
        "docker ps --format 'table {{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}' 2>/dev/null "
        "|| echo NO_ACCESS"
    ),

    # Failed systemd units
    "failed_services": "systemctl list-units --state=failed --no-legend 2>/dev/null",

    # 開放 port（排除 loopback）
    "listen_ports": "ss -tlnp | grep -v '127.0.0'",

    # 最近登入
    "last_logins": "last -n 6 2>/dev/null",

    # Auth log 失敗 (可能需要 sudo；沒權限就跳過)
    "auth_errors": (
        "grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log 2>/dev/null | tail -8"
        " || grep -i 'failed\\|invalid user' /var/log/secure 2>/dev/null | tail -8"
        " || echo NO_ACCESS"
    ),
}


# 快速模式：只跑最常用的幾項
QUICK_CHECKS = ["os_uptime", "cpu_load", "memory", "disk", "top_cpu", "zombies", "swap_consumers", "failed_services"]


def check(ip: str, session, checks: list = None) -> dict:
    """
    對指定 IP 跑健診。checks 可指定項目清單，預設全跑。
    回傳 {check_name: {"output": str, "error": str}}。
    """
    targets = checks or list(CHECKS.keys())
    results = {}
    for name in targets:
        cmd = CHECKS.get(name)
        if not cmd:
            continue
        r = run_on_ip(ip, cmd, session, timeout=20)
        results[name] = {
            "output": r["stdout"].strip(),
            "error":  r["stderr"].strip() if r["exit_code"] != 0 else "",
        }
    return results


def quick_check(ip: str, session) -> dict:
    """只跑 QUICK_CHECKS 項目，速度快。"""
    return check(ip, session, QUICK_CHECKS)


_SECTION_LABELS = {
    "os_uptime":       "OS / Uptime",
    "cpu_load":        "CPU Load / Core 數",
    "memory":          "Memory",
    "disk":            "Disk",
    "top_cpu":         "Top Processes (CPU)",
    "top_mem":         "Top Processes (MEM)",
    "zombies":         "Zombie Processes",
    "swap_consumers":  "Swap 消耗 Top 8",
    "oom_log":         "OOM Killer 記錄",
    "docker":          "Docker Containers",
    "failed_services": "Failed Services",
    "listen_ports":    "Listening Ports",
    "last_logins":     "Last Logins",
    "auth_errors":     "Auth Errors (recent)",
}


def full_report(ip: str, session, hostname: str = None, quick: bool = False) -> str:
    """
    跑健診，回傳人類可讀報告。
    quick=True 只跑常用項目（約 5 秒），full 約 15 秒。
    """
    label = hostname or ip
    data  = quick_check(ip, session) if quick else check(ip, session)
    lines = [f"{'='*60}", f"  Linux 健診報告 — {label}", f"{'='*60}"]

    for key, label_text in _SECTION_LABELS.items():
        item = data.get(key)
        if item is None:
            continue
        lines.append(f"\n【{label_text}】")
        if item.get("error"):
            lines.append(f"  (無法取得: {item['error'][:120]})")
        elif item.get("output"):
            for line in item["output"].splitlines():
                lines.append(f"  {line}")
        else:
            lines.append("  (無資料)")

    lines.append(f"\n{'='*60}")
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, getpass, argparse
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
    from tools.auth import login

    parser = argparse.ArgumentParser(description="Linux 主機標準健診")
    parser.add_argument("ip",       help="主機 IP")
    parser.add_argument("-u", "--user", default="infra.ro", help="AD 帳號 (預設 infra.ro)")
    parser.add_argument("-q", "--quick", action="store_true", help="快速模式（只跑常用項目）")
    args = parser.parse_args()

    p    = getpass.getpass(f"密碼 ({args.user}): ")
    sess = login(args.user, p)
    print(full_report(args.ip, sess, quick=args.quick))
