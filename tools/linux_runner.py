"""
Linux server 診斷工具 — 以 infra_ldap 帳號 SSH 執行，各功能獨立可呼叫。

設計原則：
  - ssh(host, cmd)         最底層，host 可為 IP 或 inventory label
  - get_*()                各回傳結構化 dict，方便程式判斷
  - health_report(host)    彙整全部，給晨報或快速巡檢用

sudo 前提：目標主機 /etc/sudoers.d/ 已設定：
  infra_ldap ALL=(ALL) NOPASSWD: /usr/sbin/ss, /usr/bin/journalctl, /usr/sbin/dmidecode
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

LINUX_USER = os.getenv("LINUX_USER", "infra_ldap")
LINUX_PASS = _secret("LDAP_SVC_PASS")
_SSH_USERS = [LINUX_USER, "infra.ro"]  # fallback order


# ── SSH 底層 ──────────────────────────────────────────────────

def _resolve_host(host: str) -> str:
    """label → IP，若已是 IP 則直接回傳。"""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    try:
        import yaml
        inv = yaml.safe_load(open(ROOT / "inventory.yaml"))
        node = inv.get("nodes", {}).get(host, {})
        ip = node.get("ip")
        if ip:
            return ip
    except Exception:
        pass
    raise ValueError(f"找不到主機 '{host}'，請確認 inventory.yaml 或直接給 IP")


def ssh(host: str, cmd: str, timeout: int = 20) -> dict:
    """
    對目標主機執行指令，回傳 {"stdout", "stderr", "exit_code", "host"}。
    host 可為 IP 或 inventory label（如 "crm"）。
    """
    import paramiko
    ip = _resolve_host(host)
    last_err = None
    for user in _SSH_USERS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, username=user, password=LINUX_PASS,
                           timeout=15, allow_agent=False, look_for_keys=False)
            _, out, err = client.exec_command(cmd, timeout=timeout)
            ec = out.channel.recv_exit_status()
            return {
                "host":      host,
                "ip":        ip,
                "stdout":    out.read().decode(errors="replace").strip(),
                "stderr":    err.read().decode(errors="replace").strip(),
                "exit_code": ec,
            }
        except Exception as e:
            last_err = e
        finally:
            client.close()
    return {"host": host, "ip": ip, "stdout": "", "stderr": str(last_err), "exit_code": 1}


# ── 系統資訊 ──────────────────────────────────────────────────

def get_system_info(host: str) -> dict:
    """OS、kernel、hostname、uptime。"""
    r = ssh(host, "uname -r; hostname; cat /etc/os-release | grep PRETTY_NAME; uptime -p 2>/dev/null || uptime")
    lines = r["stdout"].splitlines()
    return {
        "host":     host,
        "kernel":   lines[0] if len(lines) > 0 else "",
        "hostname": lines[1] if len(lines) > 1 else "",
        "os":       lines[2].replace('PRETTY_NAME=','').strip('"') if len(lines) > 2 else "",
        "uptime":   lines[3] if len(lines) > 3 else "",
        "raw":      r["stdout"],
        "error":    r["stderr"] if r["exit_code"] != 0 else "",
    }


def get_load(host: str) -> dict:
    """CPU 負載與核心數。"""
    r = ssh(host, "cat /proc/loadavg && nproc")
    lines = r["stdout"].splitlines()
    parts = lines[0].split() if lines else []
    try:
        load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])
        nproc = int(lines[1]) if len(lines) > 1 else 1
    except (ValueError, IndexError):
        load1 = load5 = load15 = 0.0
        nproc = 1
    return {
        "host": host, "load1": load1, "load5": load5, "load15": load15,
        "nproc": nproc, "load_per_cpu": round(load1 / nproc, 2),
        "high": load1 / nproc > 0.8,
    }


def get_memory(host: str) -> dict:
    """記憶體使用狀況（MB）。"""
    r = ssh(host, "cat /proc/meminfo | grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):'")
    mem = {}
    for line in r["stdout"].splitlines():
        k, v = line.split(":", 1)
        mem[k.strip()] = int(v.strip().split()[0])  # kB
    total = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", 0)
    used  = total - avail
    swap_total = mem.get("SwapTotal", 0)
    swap_free  = mem.get("SwapFree", 0)
    return {
        "host":       host,
        "total_mb":   total // 1024,
        "used_mb":    used  // 1024,
        "avail_mb":   avail // 1024,
        "used_pct":   round(used / total * 100, 1) if total else 0,
        "swap_total_mb": swap_total // 1024,
        "swap_used_mb":  (swap_total - swap_free) // 1024,
        "high":       used / total > 0.85 if total else False,
        "error":      r["stderr"] if r["exit_code"] != 0 else "",
    }


def get_disk(host: str) -> list:
    """各掛載點磁碟使用率，回傳 list of dict。"""
    r = ssh(host, "df -h --output=source,size,used,avail,pcent,target | grep -Ev 'tmpfs|udev|Filesystem|devtmpfs|squashfs'")
    result = []
    for line in r["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        pct = int(parts[4].replace("%", "")) if parts[4].replace("%","").isdigit() else 0
        result.append({
            "host":   host,
            "source": parts[0], "size": parts[1], "used": parts[2],
            "avail":  parts[3], "pct":  pct, "mount": parts[5],
            "high":   pct >= 85, "warn": pct >= 70,
        })
    return result


def get_ports(host: str) -> list:
    """Listening TCP/UDP ports（需要 sudo ss）。"""
    r = ssh(host, "sudo -n ss -tlnp")
    result = []
    for line in r["stdout"].splitlines():
        if not line.startswith("LISTEN"):
            continue
        parts = line.split()
        addr  = parts[3] if len(parts) > 3 else ""
        proc  = parts[5] if len(parts) > 5 else ""
        port  = addr.rsplit(":", 1)[-1] if ":" in addr else ""
        name_m = re.search(r'users:\(\("([^"]+)"', proc)
        pid_m  = re.search(r'pid=(\d+)', proc)
        result.append({
            "host":    host,
            "addr":    addr,
            "port":    port,
            "process": name_m.group(1) if name_m else "",
            "pid":     int(pid_m.group(1)) if pid_m else None,
        })
    return result


def get_services(host: str) -> dict:
    """Failed 服務與全部 active 服務清單。"""
    failed_r = ssh(host, "systemctl list-units --state=failed --no-legend 2>/dev/null")
    failed = []
    for line in failed_r["stdout"].splitlines():
        parts = line.split()
        if parts:
            failed.append({"unit": parts[0], "load": parts[1] if len(parts)>1 else "",
                           "active": parts[2] if len(parts)>2 else "", "sub": parts[3] if len(parts)>3 else ""})
    return {
        "host":        host,
        "failed":      failed,
        "failed_count": len(failed),
        "error":       failed_r["stderr"] if failed_r["exit_code"] not in (0, 1) else "",
    }


def get_journal(host: str, unit: str = None, lines: int = 30,
                since: str = None, grep: str = None) -> list:
    """
    讀取 systemd journal（需要 sudo journalctl）。
    unit:  指定 service，如 "nginx"
    since: 時間範圍，如 "1 hour ago"、"2026-05-06 00:00"
    grep:  關鍵字過濾
    """
    cmd = f"sudo -n journalctl --no-pager -n {lines}"
    if unit:
        cmd += f" -u {unit}"
    if since:
        cmd += f' --since "{since}"'
    if grep:
        cmd += f" | grep -i '{grep}'"
    r = ssh(host, cmd)
    entries = []
    for line in r["stdout"].splitlines():
        entries.append({"host": host, "line": line})
    return entries


def get_processes(host: str, n: int = 10, sort_by: str = "cpu") -> list:
    """Top N processes，sort_by: cpu | mem。"""
    key = "%cpu" if sort_by == "cpu" else "%mem"
    r = ssh(host, f"ps aux --sort=-{key} | head -{n+1}")
    result = []
    for line in r["stdout"].splitlines()[1:]:  # skip header
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        result.append({
            "host": host, "user": parts[0], "pid": parts[1],
            "cpu": parts[2], "mem": parts[3], "cmd": parts[10][:60],
        })
    return result


def network_probe(src: str, dst: str, port: int = None, timeout: int = 4) -> dict:
    """
    從 src 主機測試到 dst 的網路可達性。
    src: inventory label 或 IP（透過 SSH 執行）
    dst: 目標 IP 或 hostname
    port: 若指定，額外測試 TCP 連線
    回傳 {"src", "dst", "ping", "tcp"(optional), "traceroute"(optional)}
    """
    # ICMP ping
    r_ping = ssh(src, f"ping -c 2 -W {timeout} {dst} 2>&1")
    loss_m = re.search(r"(\d+)% packet loss", r_ping["stdout"])
    loss_pct = int(loss_m.group(1)) if loss_m else 100
    rtt_m = re.search(r"/([\d.]+)/[\d.]+/", r_ping["stdout"])
    rtt_ms = float(rtt_m.group(1)) if rtt_m else None

    result = {
        "src": src,
        "dst": dst,
        "ping": {"ok": loss_pct == 0, "loss_pct": loss_pct, "rtt_ms": rtt_ms},
    }

    # TCP port（nc 優先，fallback 到 bash /dev/tcp）
    if port:
        cmd = (
            f"nc -zw{timeout} {dst} {port} 2>/dev/null && echo TCP_OK || "
            f"(timeout {timeout} bash -c 'cat < /dev/null > /dev/tcp/{dst}/{port}' 2>/dev/null "
            f"&& echo TCP_OK || echo TCP_FAIL)"
        )
        r_tcp = ssh(src, cmd, timeout=timeout + 6)
        result["tcp"] = {"port": port, "ok": "TCP_OK" in r_tcp["stdout"]}

    # traceroute（best-effort，不影響主要結果）
    r_tr = ssh(src,
        f"traceroute -n -m 6 -w 2 {dst} 2>/dev/null || tracepath -n -b {dst} 2>/dev/null",
        timeout=20)
    if r_tr["stdout"]:
        result["traceroute"] = r_tr["stdout"]

    return result


def get_logins(host: str, n: int = 10) -> list:
    """最近登入紀錄。"""
    r = ssh(host, f"last -n {n} -w 2>/dev/null | head -{n}")
    result = []
    for line in r["stdout"].splitlines():
        if line.strip() and not line.startswith("wtmp"):
            result.append({"host": host, "line": line})
    return result


def get_hardware(host: str) -> dict:
    """硬體資訊（需要 sudo dmidecode）。"""
    sys_r = ssh(host, "sudo -n dmidecode -t system 2>/dev/null | grep -E 'Manufacturer|Product Name|Serial Number'")
    mem_r = ssh(host, "sudo -n dmidecode -t memory 2>/dev/null | grep -E 'Size:|Type:|Speed:' | grep -v 'No Module'")
    return {
        "host":   host,
        "system": sys_r["stdout"],
        "memory": mem_r["stdout"],
        "error":  sys_r["stderr"] or mem_r["stderr"],
    }


# ── 資安代理程式 ──────────────────────────────────────────────

def get_security_agents(host: str) -> dict:
    """檢查資安代理程式安裝狀態（SentinelOne、Wazuh、ApexOne）。

    回傳每個 agent 的 installed: bool 與 status: str。
    """
    checks = {
        "sentinelone": "systemctl status sentinelone 2>/dev/null || dpkg -l 2>/dev/null | grep -qi sentinel && echo installed || rpm -qa 2>/dev/null | grep -qi sentinel && echo installed || echo not_found",
        "wazuh":       "systemctl is-active wazuh-agent 2>/dev/null || echo not_found",
        "apexone":     "systemctl is-active ds_agent 2>/dev/null || dpkg -l 2>/dev/null | grep -qi 'apex\\|ds_agent' && echo installed || rpm -qa 2>/dev/null | grep -qi 'apex\\|ds_agent' && echo installed || echo not_found",
    }

    result = {}
    for agent, cmd in checks.items():
        r = ssh(host, cmd)
        out = (r.get("stdout") or "").strip().lower()
        if "not_found" in out or not out:
            result[agent] = {"installed": False, "status": "not installed"}
        elif "active" in out:
            result[agent] = {"installed": True, "status": "active"}
        elif "inactive" in out:
            result[agent] = {"installed": True, "status": "inactive"}
        else:
            result[agent] = {"installed": True, "status": out.splitlines()[0][:40]}
    return result


# ── 服務特定檢查 ──────────────────────────────────────────────

def check_nginx(host: str) -> dict:
    """Nginx 狀態 + 最近 error log。"""
    status_r = ssh(host, "systemctl is-active nginx 2>/dev/null")
    config_r = ssh(host, "nginx -t 2>&1")
    errors_r = ssh(host, "sudo -n journalctl -u nginx --no-pager -n 20 | grep -i 'error\\|crit\\|emerg' | tail -5")
    return {
        "host":   host,
        "active": status_r["stdout"].strip() == "active",
        "config_ok": "syntax is ok" in config_r["stderr"].lower() or "syntax is ok" in config_r["stdout"].lower(),
        "recent_errors": errors_r["stdout"].splitlines(),
    }


def check_mysql(host: str) -> dict:
    """MySQL/MariaDB 狀態 + 連線數。"""
    active_r = ssh(host, "systemctl is-active mysqld mariadb 2>/dev/null | head -1")
    conn_r   = ssh(host, "mysqladmin -u root status 2>/dev/null | grep -oE 'Threads: [0-9]+'")
    return {
        "host":    host,
        "active":  active_r["stdout"].strip() == "active",
        "threads": conn_r["stdout"].strip(),
        "error":   active_r["stderr"],
    }


# ── 彙整健康報告 ──────────────────────────────────────────────

def health_report(host: str) -> str:
    """一次跑完所有檢查，回傳人類可讀的文字報告。"""
    info    = get_system_info(host)
    load    = get_load(host)
    mem     = get_memory(host)
    disks   = get_disk(host)
    ports   = get_ports(host)
    svcs    = get_services(host)
    procs   = get_processes(host, n=5)

    try:
        ip = _resolve_host(host)
    except ValueError:
        ip = host
    label = info.get("hostname") or host
    lines = ["=" * 58, f"  Linux 健診 — {label} ({ip})", "=" * 58]

    # 系統
    lines.append(f"\n  OS:     {info['os']}")
    lines.append(f"  Kernel: {info['kernel']}  Uptime: {info['uptime']}")

    # 資源
    load_icon = "🔴" if load["high"] else "✅"
    mem_icon  = "🔴" if mem["high"] else "✅"
    lines.append(f"\n【資源】")
    lines.append(f"  {load_icon} CPU Load: {load['load1']} / {load['load5']} / {load['load15']}  ({load['nproc']} cores, {load['load_per_cpu']} per core)")
    lines.append(f"  {mem_icon} Memory: {mem['used_mb']:,} / {mem['total_mb']:,} MB  ({mem['used_pct']}%)")
    if mem["swap_total_mb"] > 0:
        lines.append(f"     Swap: {mem['swap_used_mb']:,} / {mem['swap_total_mb']:,} MB")

    # 磁碟
    lines.append(f"\n【磁碟】")
    for d in disks:
        icon = "🔴" if d["high"] else ("🟡" if d["warn"] else "✅")
        lines.append(f"  {icon} {d['mount']:20s}  {d['used']:>6} / {d['size']:>6}  ({d['pct']}%)")

    # 服務
    lines.append(f"\n【服務】")
    if svcs["failed"]:
        for s in svcs["failed"]:
            lines.append(f"  ❌ {s['unit']}")
    else:
        lines.append("  ✅ 無 failed service")

    # Ports
    lines.append(f"\n【Listening Ports】")
    for p in ports:
        lines.append(f"  :{p['port']:5s}  {p['process']}")

    # Top processes
    lines.append(f"\n【Top Processes (CPU)】")
    for p in procs:
        lines.append(f"  {p['cpu']:>5}%  {p['mem']:>5}%  {p['cmd']}")

    lines.append("\n" + "=" * 58)
    return "\n".join(lines)


def get_idle_timeout(host: str) -> dict:
    """查詢 SSH / shell 閒置登出設定。

    回傳:
      tmout:                  int|None — bash TMOUT（秒），None = 未設定
      client_alive_interval:  int      — sshd ClientAliveInterval（秒），0 = 未啟用
      client_alive_count_max: int      — sshd ClientAliveCountMax
      tcp_keepalive_time:     int      — OS TCP keepalive 開始時間（秒）
      effective_ssh_timeout:  int|None — 實際 SSH idle 斷線時間（秒），None = 無限
    """
    tmout_r = ssh(host, "grep -rh TMOUT /etc/profile /etc/profile.d/ /etc/bash.bashrc ~/.bashrc 2>/dev/null | grep -v '^#' | head -1")
    sshd_r  = ssh(host, "grep -E '^ClientAliveInterval|^ClientAliveCountMax' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
    tcp_r   = ssh(host, "sysctl -n net.ipv4.tcp_keepalive_time")

    # TMOUT
    tmout = None
    for line in tmout_r.get("stdout", "").splitlines():
        if "TMOUT" in line:
            try:
                tmout = int(line.split("=")[-1].strip())
            except ValueError:
                pass

    # ClientAlive
    interval, count = 0, 3
    for line in sshd_r.get("stdout", "").splitlines():
        if line.startswith("ClientAliveInterval"):
            try:
                interval = int(line.split()[-1])
            except ValueError:
                pass
        if line.startswith("ClientAliveCountMax"):
            try:
                count = int(line.split()[-1])
            except ValueError:
                pass

    # TCP keepalive
    try:
        tcp_keepalive = int(tcp_r.get("stdout", "7200").strip())
    except ValueError:
        tcp_keepalive = 7200

    # SSH idle 斷線 = interval * count（0 = 不斷）
    effective = (interval * count) if interval > 0 else None

    return {
        "tmout":                  tmout,
        "client_alive_interval":  interval,
        "client_alive_count_max": count,
        "tcp_keepalive_time":     tcp_keepalive,
        "effective_ssh_timeout":  effective,
    }


# ── CLI ──────────────────────────────────────────────────────

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "crm"
    cmd  = sys.argv[2] if len(sys.argv) > 2 else "report"

    if cmd == "report":
        print(health_report(host))
    elif cmd == "ports":
        for p in get_ports(host):
            print(f":{p['port']:5s}  {p['process']}")
    elif cmd == "disk":
        for d in get_disk(host):
            icon = "🔴" if d["high"] else ("🟡" if d["warn"] else "✅")
            print(f"{icon} {d['mount']:25s} {d['used']}/{d['size']} ({d['pct']}%)")
    elif cmd == "log":
        unit  = sys.argv[3] if len(sys.argv) > 3 else None
        since = sys.argv[4] if len(sys.argv) > 4 else "1 hour ago"
        for e in get_journal(host, unit=unit, since=since):
            print(e["line"])
    elif cmd == "probe":
        dst  = sys.argv[3] if len(sys.argv) > 3 else "8.8.8.8"
        port = int(sys.argv[4]) if len(sys.argv) > 4 else None
        r = network_probe(host, dst, port=port)
        ping = r["ping"]
        icon = "✅" if ping["ok"] else "❌"
        rtt  = f"  rtt={ping['rtt_ms']}ms" if ping["rtt_ms"] else ""
        print(f"{icon} ping {host} → {dst}  loss={ping['loss_pct']}%{rtt}")
        if "tcp" in r:
            tip = "✅" if r["tcp"]["ok"] else "❌"
            print(f"{tip} tcp  {host} → {dst}:{r['tcp']['port']}")
        if "traceroute" in r:
            print(r["traceroute"])
    elif cmd == "ssh":
        raw_cmd = " ".join(sys.argv[3:])
        r = ssh(host, raw_cmd)
        print(r["stdout"])
        if r["stderr"]:
            print(f"[stderr] {r['stderr']}")
    elif cmd == "security-agents":
        r = get_security_agents(host)
        for agent, info in r.items():
            icon = "✅" if info["installed"] else "❌"
            print(f"{icon} {agent:<15} {info['status']}")
    elif cmd == "idle-timeout":
        r = get_idle_timeout(host)
        print(f"TMOUT (bash)          : {r['tmout']} 秒" if r['tmout'] else "TMOUT (bash)          : 未設定")
        print(f"ClientAliveInterval   : {r['client_alive_interval']} 秒")
        print(f"ClientAliveCountMax   : {r['client_alive_count_max']}")
        print(f"TCP keepalive_time    : {r['tcp_keepalive_time']} 秒")
        if r['effective_ssh_timeout']:
            t = r['effective_ssh_timeout']
            print(f"SSH 實際斷線時間      : {t} 秒 ({t // 60} 分鐘)")
        else:
            print(f"SSH 實際斷線時間      : 無限（依賴防火牆 session TTL）")
    else:
        print(f"Usage: linux_runner.py <host> [report|ports|disk|log|probe|ssh|idle-timeout] [args...]")
