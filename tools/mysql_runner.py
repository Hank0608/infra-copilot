"""MySQL 診斷工具 — 全程透過 SSH，不需要 MySQL 帳號。"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tools.ssh_runner import run as _ssh

_SLOW_LOG  = "/var/log/mysql/mysql-slow.log"
_ERROR_LOG = "/var/log/mysql/error.log"
_MYSQLD    = "mysqld"


# ── 1. Slow query log ─────────────────────────────────────────

def get_slow_queries(node: str, lines: int = 5000, top_n: int = 20) -> list:
    """
    解析 slow query log，回傳前 top_n 筆（依 Query_time 降冪）。
    每筆: {query_time, lock_time, rows_examined, rows_sent, ts, query}
    """
    r = _ssh(node, f"sudo tail -n {lines} {_SLOW_LOG} 2>/dev/null || tail -n {lines} {_SLOW_LOG} 2>/dev/null")
    raw = r["stdout"]
    if not raw.strip():
        return []

    records, cur = [], {}
    for line in raw.splitlines():
        if line.startswith("# Time:"):
            if cur.get("query"):
                records.append(cur)
            cur = {"ts": line[8:].strip(), "query": ""}
        elif line.startswith("# Query_time:"):
            m = re.search(
                r"Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)"
                r"\s+Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)", line
            )
            if m:
                cur["query_time"]    = float(m.group(1))
                cur["lock_time"]     = float(m.group(2))
                cur["rows_sent"]     = int(m.group(3))
                cur["rows_examined"] = int(m.group(4))
        elif not line.startswith("#") and line.strip() and not line.startswith("SET ") and not line.startswith("use "):
            cur["query"] = (cur.get("query", "") + " " + line.strip()).strip()[:300]

    if cur.get("query"):
        records.append(cur)

    records.sort(key=lambda x: x.get("query_time", 0), reverse=True)
    return records[:top_n]


# ── 2. Error log ──────────────────────────────────────────────

def get_error_log(node: str, lines: int = 200) -> list:
    """
    讀取 MySQL error log，回傳結構化紀錄。
    只保留 ERROR / Warning 層級，略過 Note。
    每筆: {ts, level, message}
    """
    r = _ssh(node, f"sudo tail -n {lines} {_ERROR_LOG} 2>/dev/null || tail -n {lines} {_ERROR_LOG} 2>/dev/null")
    records = []
    for line in r["stdout"].splitlines():
        # MySQL 8.x 格式: 2026-05-13T10:00:00.000000Z 0 [ERROR] ...
        m = re.match(r"(\S+)\s+\d+\s+\[(\w+)\]\s+(.*)", line)
        if m:
            level = m.group(2)
            if level in ("ERROR", "Warning"):
                records.append({
                    "ts":      m.group(1),
                    "level":   level,
                    "message": m.group(3)[:200],
                })
    return records


# ── 3. 連線數 ─────────────────────────────────────────────────

def get_connections(node: str) -> dict:
    """
    透過 ss 統計 3306 port 連線狀態。
    回傳 {established, time_wait, total, top_clients}
    top_clients: [(ip, count), ...]
    """
    r = _ssh(node, "ss -tn state established '( dport = :3306 or sport = :3306 )' 2>/dev/null")
    lines = [l for l in r["stdout"].splitlines() if re.search(r'\d+\.\d+', l)]

    from collections import Counter
    clients = Counter()
    for line in lines:
        parts = line.split()
        # peer address 在第4欄 (Recv-Q Send-Q Local Peer)
        if len(parts) >= 5:
            peer = parts[4].rsplit(":", 1)[0].strip("[]")
            clients[peer] += 1

    r2 = _ssh(node, "ss -tn '( dport = :3306 or sport = :3306 )' 2>/dev/null | tail -n +2 | wc -l")
    total = int(r2["stdout"].strip() or 0)

    r3 = _ssh(node, "ss -tn state time-wait '( dport = :3306 or sport = :3306 )' 2>/dev/null | tail -n +2 | wc -l")
    tw = int(r3["stdout"].strip() or 0)

    return {
        "established": len(lines),
        "time_wait":   tw,
        "total":       total,
        "top_clients": clients.most_common(10),
    }


# ── 4. Process 記憶體 / CPU ───────────────────────────────────

def get_process_stats(node: str) -> dict:
    """
    回傳 mysqld process 的 CPU / RSS / VSZ。
    {pid, cpu_pct, mem_pct, rss_mb, vsz_mb, uptime_str}
    """
    r = _ssh(node, f"ps aux | grep -E '[m]ysqld$|[m]ysqld ' | grep -v grep | head -1")
    line = r["stdout"].strip().splitlines()[0] if r["stdout"].strip() else ""
    if not line:
        return {}

    parts = line.split()
    try:
        return {
            "pid":      parts[1],
            "cpu_pct":  float(parts[2]),
            "mem_pct":  float(parts[3]),
            "vsz_mb":   round(int(parts[4]) / 1024, 1),
            "rss_mb":   round(int(parts[5]) / 1024, 1),
            "uptime_str": parts[9] if len(parts) > 9 else "",
        }
    except (IndexError, ValueError):
        return {"raw": line}


# ── 5. 磁碟 I/O ───────────────────────────────────────────────

def get_disk_io(node: str, datadir: str = "/var/lib/mysql") -> dict:
    """
    用 iostat 量 MySQL datadir 所在裝置的 I/O 壓力。
    回傳 {device, await_ms, util_pct, r_iops, w_iops, r_mbps, w_mbps}
    """
    # 先找 datadir 的裝置
    r = _ssh(node, f"df {datadir} 2>/dev/null | tail -1")
    dev_line = r["stdout"].strip()
    device = dev_line.split()[0] if dev_line else ""
    dev_name = device.rsplit("/", 1)[-1] if device else ""

    if not dev_name:
        return {"error": f"無法取得 {datadir} 的裝置名稱"}

    # iostat -x 採樣 3 次，取最後一次（排除冷啟動）
    r2 = _ssh(node, f"iostat -xd {dev_name} 1 3 2>/dev/null | grep -E '^{dev_name}' | tail -1", timeout=15)
    line = r2["stdout"].strip()
    if not line:
        return {"device": dev_name, "error": "iostat 無輸出（可能需要 sysstat 套件）"}

    parts = line.split()
    # iostat -x 欄位順序（Linux sysstat）:
    # Device r/s w/s rkB/s wkB/s rrqm/s wrqm/s %rrqm %wrqm r_await w_await aqu-sz rareq-sz wareq-sz svctm %util
    try:
        return {
            "device":   dev_name,
            "r_iops":   float(parts[1]),
            "w_iops":   float(parts[2]),
            "r_mbps":   round(float(parts[3]) / 1024, 2),
            "w_mbps":   round(float(parts[4]) / 1024, 2),
            "r_await":  float(parts[9]),
            "w_await":  float(parts[10]),
            "util_pct": float(parts[-1]),
        }
    except (IndexError, ValueError):
        return {"device": dev_name, "raw": line}


# ── 6. 一鍵診斷 ───────────────────────────────────────────────

def diagnose(node: str) -> str:
    """完整診斷：process → 連線 → I/O → error log → slow query top5。"""
    lines = ["=" * 55, f"  MySQL 診斷  [{node}]", "=" * 55]

    # Process
    proc = get_process_stats(node)
    if proc and "pid" in proc:
        lines.append(f"【Process】PID {proc['pid']}  CPU {proc['cpu_pct']}%  "
                     f"RSS {proc['rss_mb']:.0f} MB  MEM {proc['mem_pct']}%")
    else:
        lines.append("【Process】mysqld 未執行或無法取得")

    # 連線
    conn = get_connections(node)
    lines.append(f"【連線】ESTABLISHED {conn['established']}  TIME_WAIT {conn['time_wait']}  TOTAL {conn['total']}")
    if conn["top_clients"]:
        top = "  ".join(f"{ip}({n})" for ip, n in conn["top_clients"][:5])
        lines.append(f"  Top clients: {top}")

    # I/O
    io = get_disk_io(node)
    if "error" in io:
        lines.append(f"【磁碟 I/O】{io.get('error', io)}")
    else:
        lines.append(f"【磁碟 I/O】{io['device']}  "
                     f"r={io['r_iops']:.0f} IOPS / w={io['w_iops']:.0f} IOPS  "
                     f"r_await={io['r_await']} ms / w_await={io['w_await']} ms  "
                     f"util={io['util_pct']}%")

    # Error log
    errors = get_error_log(node, lines=100)
    if errors:
        lines.append(f"【Error Log】最近 {len(errors)} 筆 ERROR/Warning")
        for e in errors[-5:]:
            lines.append(f"  [{e['level']}] {e['ts'][:19]}  {e['message'][:100]}")
    else:
        lines.append("【Error Log】✅ 無 ERROR / Warning")

    # Slow queries
    slow = get_slow_queries(node, lines=2000, top_n=5)
    if slow:
        lines.append(f"【Slow Query Top 5】")
        for i, q in enumerate(slow, 1):
            lines.append(f"  {i}. {q.get('query_time', 0):.2f}s  "
                         f"rows_examined={q.get('rows_examined', 0)}  "
                         f"{q.get('query', '')[:100]}")
    else:
        lines.append("【Slow Query】✅ 無慢查詢紀錄（或 log 為空）")

    lines.append("=" * 55)
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd  = sys.argv[1] if len(sys.argv) > 1 else "diagnose"
    node = sys.argv[2] if len(sys.argv) > 2 else "cloud-db"

    if cmd == "diagnose":
        print(diagnose(node))

    elif cmd == "slow":
        top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        rows  = get_slow_queries(node, top_n=top_n)
        if not rows:
            print("無慢查詢紀錄")
        for i, r in enumerate(rows, 1):
            print(f"{i:2d}. {r.get('query_time', 0):7.2f}s  "
                  f"examined={r.get('rows_examined', 0):8d}  {r.get('query', '')[:120]}")

    elif cmd == "io":
        print(get_disk_io(node))

    elif cmd == "conn":
        print(get_connections(node))

    elif cmd == "proc":
        print(get_process_stats(node))

    elif cmd == "errors":
        for e in get_error_log(node):
            print(f"[{e['level']}] {e['ts'][:19]}  {e['message']}")

    else:
        print("Usage: mysql_runner.py [diagnose|slow|io|conn|proc|errors] [node] [top_n]")
        sys.exit(1)
