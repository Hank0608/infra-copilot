"""Dell PowerVault ME4/ME5 SAN replication monitor — SSH XML CLI，支援多台。"""

import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

ME_HOSTS = [h.strip() for h in os.getenv("ME_HOSTS", "10.200.202.10").split(",") if h.strip()]

# 各台 ME 帳號不同：ME4024(.10/.14/.16) 用 infra_ldap，ME5024(.12) 用 infra.ro
_HOST_CREDS = {
    "10.200.202.10": ("infra.ro", _secret("AD_PASS")),
    "10.200.202.12": ("infra.ro", _secret("AD_PASS")),
    "10.200.202.14": ("infra.ro", _secret("AD_PASS")),
    "10.200.202.16": ("infra.ro", _secret("AD_PASS")),
}
_DEFAULT_CREDS = ("infra.ro", _secret("AD_PASS"))

_TZ8 = timezone(timedelta(hours=8))

_REP_STATUS = {
    0: ("Unsynchronized", "❌"),
    1: ("Synchronized",   "✅"),
    2: ("Replicating",    "🔄"),
    3: ("Suspended",      "⚠️"),
    4: ("Ready",          "✅"),
    5: ("Not Configured", "⬜"),
}
_RUN_STATUS = {0: "❌ Failed", 1: "✅ Success", 2: "⚠️ Unknown"}


def _ssh_cmd(host: str, cmd: str) -> str:
    import paramiko
    user, pw = _HOST_CREDS.get(host, _DEFAULT_CREDS)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=pw,
                   timeout=15, allow_agent=False, look_for_keys=False)
    try:
        _, stdout, _ = client.exec_command(cmd)
        return stdout.read().decode("utf-8", errors="replace")
    finally:
        client.close()


def _get(name: str, text: str) -> str:
    m = re.search(rf'name="{name}"[^>]*>([^<]*)<', text)
    return m.group(1).strip() if m else ""


# ── Per-host queries ──────────────────────────────────────────

def _parse_dt(ts_str: str):
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_TZ8) if ts_str else None
    except ValueError:
        return None


def _parse_run_obj(b: str, host: str, set_name: str) -> dict:
    """解析單個 cs-replication 物件為 run dict。"""
    ts   = _get("time-start", b)
    te   = _get("time-end", b)
    st   = _parse_dt(ts)
    en   = _parse_dt(te)
    dur  = int((en - st).total_seconds() / 60) if st and en and en > st else None
    data_str = _get("total-data-transferred", b)         # e.g. "727.9GB"
    data_num = int(_get("total-data-transferred-numeric", b) or 0)
    data_gb  = round(data_num / 1024**3, 1) if data_num else 0.0
    prog = _get("progress", b)
    state = _get("replication-state", b)                 # "Last Run" / "Current Run"
    err  = int(_get("error-count", b) or 0)
    result = "OK" if err == 0 and prog == "100%" else ("ABORT" if prog != "100%" else "ERROR")
    return {
        "host":    host,
        "set":     set_name,
        "state":   state,
        "start":   st,
        "end":     en,
        "result":  result,
        "dur_min": dur,
        "data_gb": data_gb,
        "data_str": data_str,
        "progress": prog,
        "errors":  err,
    }


def get_replication_sets(host: str) -> list:
    raw = _ssh_cmd(host, "show replication-sets")

    # 先取 cs-replication-set（set 定義）
    set_blocks = re.findall(r'<OBJECT basetype="cs-replication-set".*?</OBJECT>', raw, re.DOTALL)
    # 再取 cs-replication（run 紀錄），每個 set 有 2 筆（Last Run + Current Run）
    run_blocks = re.findall(r'<OBJECT basetype="cs-replication".*?</OBJECT>', raw, re.DOTALL)

    result = []
    for i, b in enumerate(set_blocks):
        ts_str  = _get("last-success-time", b)
        last_dt = _parse_dt(ts_str)
        st_num  = int(_get("status-numeric", b) or 0)
        run_num = int(_get("last-run-status-numeric", b) or 2)
        name    = _get("name", b)

        # 每個 set 對應 2 個 run block（Last Run, Current Run）
        runs = []
        for rb in run_blocks[i * 2: i * 2 + 2]:
            runs.append(_parse_run_obj(rb, host, name))

        result.append({
            "host":         host,
            "name":         name,
            "peer":         _get("peer-connection-name", b),
            "primary_vol":  _get("primary-volume-name", b),
            "status":       _get("status", b),
            "status_num":   st_num,
            "active":       _get("sync-job-active", b) == "True",
            "last_run":     _get("last-run-status", b),
            "last_run_num": run_num,
            "last_success": last_dt,
            "queue_count":  int(_get("queue-count", b) or 0),
            "runs":         runs,
        })
    return result


def get_disk_groups(host: str) -> list:
    """
    回傳 disk group 清單，含 VRSC 狀態。
    fields: name, status, health, raid, size_gb, free_gb, job, job_pct
    job: 'VRSC' | 'Reconstructing' | '' 等
    """
    raw    = _ssh_cmd(host, "show disk-groups")
    blocks = re.findall(r'<OBJECT basetype="disk-groups".*?</OBJECT>', raw, re.DOTALL)
    def _to_gb(raw_val: str) -> float:
        """'7176.2GB' → 7176.2, '28.7TB' → 29388.8, '0B' → 0"""
        v = raw_val.strip()
        num = float(re.sub(r'[^\d.]', '', v) or 0)
        if v.endswith("TB"):
            return round(num * 1024, 1)
        return round(num, 1)  # assume GB

    result = []
    for b in blocks:
        result.append({
            "host":     host,
            "name":     _get("name", b),
            "status":   _get("status", b),
            "health":   _get("health", b),
            "raid":     _get("raidtype", b),
            "size_gb":  _to_gb(_get("size", b) or "0"),
            "free_gb":  _to_gb(_get("freespace", b) or "0"),
            "job":      _get("current-job", b),
            "job_pct":  _get("current-job-completion", b),
        })
    return result


def get_peer_connections(host: str) -> list:
    raw    = _ssh_cmd(host, "show peer-connections")
    blocks = re.findall(r'<OBJECT basetype="peer-connections".*?</OBJECT>', raw, re.DOTALL)
    result = []
    for b in blocks:
        result.append({
            "host":       host,
            "name":       _get("peer-connection-name", b),
            "type":       _get("connection-type", b),
            "status":     _get("connection-status", b),
            "status_num": int(_get("connection-status-numeric", b) or 0),
            "health":     _get("health", b),
        })
    return result


def _parse_events(host: str, raw: str, hours: int = 24, max_events: int = 500) -> list:
    blocks = re.findall(r'<OBJECT basetype="events".*?</OBJECT>', raw, re.DOTALL)
    cutoff = datetime.now(tz=_TZ8) - timedelta(hours=hours)
    result = []
    for b in blocks[:max_events]:
        ts_str = _get("time-stamp", b)
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_TZ8)
        except ValueError:
            dt = None
        if dt and dt < cutoff:
            break
        sev = _get("severity", b)
        msg = _get("message", b)
        if "eplica" in msg or sev in ("WARNING", "ERROR", "CRITICAL"):
            result.append({
                "host":     host,
                "time":     dt,
                "severity": sev,
                "message":  msg,
            })
    return result


def _parse_runs(host: str, raw: str, hours: int = 48) -> list:
    blocks = re.findall(r'<OBJECT basetype="events".*?</OBJECT>', raw, re.DOTALL)
    cutoff = datetime.now(tz=_TZ8) - timedelta(hours=hours)
    rep_events = []
    for b in blocks[:1000]:
        ts_str = _get("time-stamp", b)
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_TZ8)
        except ValueError:
            dt = None
        if dt and dt < cutoff:
            break
        msg = _get("message", b)
        if "eplica" not in msg:
            continue
        rset_m = re.search(r'replication set name: ([^,)]+)', msg)
        if not rset_m:
            continue
        rset = rset_m.group(1).strip()
        if "completed successfully" in msg:
            kind = "OK"
        elif "aborted" in msg.lower():
            kind = "ABORT"
        elif "was started" in msg:
            kind = "START"
        else:
            continue
        rep_events.append({"time": dt, "kind": kind, "set": rset})

    pending_end: dict = {}
    runs = []
    for ev in rep_events:
        sname = ev["set"]
        if ev["kind"] in ("OK", "ABORT"):
            pending_end[sname] = {"end": ev["time"], "result": ev["kind"]}
        elif ev["kind"] == "START":
            if sname in pending_end:
                pe  = pending_end.pop(sname)
                dur = int((pe["end"] - ev["time"]).total_seconds() / 60)
                runs.append({
                    "host":    host,
                    "set":     sname,
                    "start":   ev["time"],
                    "end":     pe["end"],
                    "result":  pe["result"],
                    "dur_min": dur,
                })
            else:
                runs.append({
                    "host":    host,
                    "set":     sname,
                    "start":   ev["time"],
                    "end":     None,
                    "result":  "RUNNING",
                    "dur_min": None,
                })
    return runs


def get_recent_events(host: str, hours: int = 24) -> list:
    return _parse_events(host, _ssh_cmd(host, "show events"), hours=hours)


def get_replication_runs(host: str, hours: int = 48) -> list:
    return _parse_runs(host, _ssh_cmd(host, "show events"), hours=hours)


# ── 全站彙整（並行） ──────────────────────────────────────────

def get_all_hosts(hours: int = 24) -> dict:
    """並行查詢所有 ME hosts，回傳 {host: {rep_sets, peers, events, runs, error}}。"""
    def _fetch(host):
        try:
            raw_events = _ssh_cmd(host, "show events")
            rep_sets   = get_replication_sets(host)
            return host, {
                "rep_sets": rep_sets,
                "peers":    get_peer_connections(host),
                "events":   _parse_events(host, raw_events, hours=hours),
                "error":    None,
            }
        except Exception as e:
            return host, {"rep_sets": [], "peers": [], "events": [], "error": str(e)}

    results = {}
    with ThreadPoolExecutor(max_workers=len(ME_HOSTS)) as ex:
        for host, data in ex.map(_fetch, ME_HOSTS):
            results[host] = data
    return results


# ── 報告 ──────────────────────────────────────────────────────

def dedup_runs(all_data: dict) -> dict:
    """
    從所有 host 的 rep_sets 彙整 runs，以 (set_name, state) 去重。
    ME_HOSTS 順序 source 在前（.10/.12 先於 .14/.16），故保留第一筆即為 source 端。
    回傳 {set_name: [run, ...]}。
    """
    seen: set = set()
    result: dict = {}
    for host in ME_HOSTS:
        for rs in all_data.get(host, {}).get("rep_sets", []):
            for r in rs.get("runs", []):
                key = (r["set"], r["state"])
                if key not in seen:
                    seen.add(key)
                    result.setdefault(r["set"], []).append(r)
    return result


def dedup_sets(all_data: dict) -> list:
    """
    從所有 host 的 rep_sets 去重，每個 set name 只保留 source 端那筆。
    """
    seen: set = set()
    result: list = []
    for host in ME_HOSTS:
        for rs in all_data.get(host, {}).get("rep_sets", []):
            if rs["name"] not in seen:
                seen.add(rs["name"])
                result.append(rs)
    return result


def get_system_info(host: str) -> dict:
    """回傳 {host, model, name}，如 model='ME4024'。"""
    raw = _ssh_cmd(host, "show system")
    return {
        "host":  host,
        "model": _get("product-id", raw),
        "name":  _get("system-name", raw),
    }


def get_disk_summary(host: str) -> dict:
    """
    回傳 {host, total, arch, types, sizes_gb, models}。
    arch: {'HDD': N, 'SSD': N}
    types: {'SAS': N, 'NVMe': N, ...}
    """
    from collections import Counter
    raw = _ssh_cmd(host, "show disks")
    archs   = re.findall(r'name="architecture"\s[^>]+>(\w+)<', raw)
    descs   = re.findall(r'name="description"\s[^>]+type="string"[^>]+>(\w+)<', raw)
    models  = re.findall(r'name="model"\s[^>]+>([^<]+)<', raw)
    blocks  = re.findall(r'name="blocks"\sblocksize="512"[^>]+>(\d+)<', raw)
    sizes   = sorted({round(int(b) * 512 / 1024 ** 3) for b in blocks})
    return {
        "host":     host,
        "total":    len(archs),
        "arch":     dict(Counter(archs)),
        "types":    dict(Counter(descs)),
        "sizes_gb": sizes,
        "models":   dict(Counter(models)),
    }


def get_all_system_info() -> list:
    """回傳所有 ME_HOSTS 的 system info + disk summary 合併結果。"""
    results = []
    for host in ME_HOSTS:
        try:
            info = get_system_info(host)
            disk = get_disk_summary(host)
            info.update(disk)
            results.append(info)
        except Exception as e:
            results.append({"host": host, "error": str(e)})
    return results


def get_controller_stats(host: str) -> list[dict]:
    """
    回傳控制器 I/O 統計。
    fields: host, controller, cpu_pct, iops, bps, wr_cache_pct, rd_hit_pct, wr_hit_pct
    wr_cache_pct: 寫入 cache 使用率（%），正常高值不代表異常
    rd_hit_pct: 讀取 cache 命中率；<50% 代表多數讀取直接打磁碟
    """
    raw    = _ssh_cmd(host, "show controller-statistics")
    blocks = re.findall(r'<OBJECT basetype="controller-statistics".*?</OBJECT>', raw, re.DOTALL)
    result = []
    for b in blocks:
        try:
            rd_hit = float(_get("read-cache-hits", b) or 0)
            wr_hit = float(_get("write-cache-hits", b) or 0)
        except ValueError:
            rd_hit = wr_hit = 0.0
        result.append({
            "host":         host,
            "controller":   _get("durable-id", b),
            "cpu_pct":      int(_get("cpu-load", b) or 0),
            "iops":         int(_get("iops", b) or 0),
            "bps":          _get("bytes-per-second", b),
            "wr_cache_pct": int(_get("write-cache-used", b) or 0),
            "rd_hits":      int(rd_hit),   # 累計 count
            "wr_hits":      int(wr_hit),   # 累計 count
        })
    return result


def get_volume_stats(host: str) -> list[dict]:
    """
    回傳 volume I/O 統計。
    fields: host, volume, iops, bps, rd_hit_pct, wr_hit_pct, read_rsp_us, write_rsp_us
    read_rsp_us / write_rsp_us: 微秒 (μs)
    """
    raw    = _ssh_cmd(host, "show volume-statistics")
    blocks = re.findall(r'<OBJECT basetype="volume-statistics".*?</OBJECT>', raw, re.DOTALL)
    result = []
    for b in blocks:
        try:
            rd_hit = float(_get("read-cache-hits", b) or 0)
            wr_hit = float(_get("write-cache-hits", b) or 0)
        except ValueError:
            rd_hit = wr_hit = 0.0
        result.append({
            "host":         host,
            "volume":       _get("volume-name", b),
            "iops":         int(_get("iops", b) or 0),
            "bps":          _get("bytes-per-second", b),
            "rd_hits":      int(rd_hit),   # 累計 count，非百分比
            "wr_hits":      int(wr_hit),   # 累計 count，非百分比
            "read_rsp_us":  int(_get("avg-read-rsp-time", b) or 0),
            "write_rsp_us": int(_get("avg-write-rsp-time", b) or 0),
        })
    return result


def get_dg_stats(host: str) -> list[dict]:
    """
    回傳 disk group I/O 統計，含延遲。
    fields: host, name, iops, bps, read_rsp_us, write_rsp_us
    延遲單位：微秒 (μs)。HDD 正常 <20000μs (20ms)；>50000μs WARN；>100000μs CRITICAL
    ME4024 (RAID5 HDD) baseline 可到 20-50ms，ME5024 (ADAPT) 通常 <10ms
    """
    raw    = _ssh_cmd(host, "show disk-group-statistics")
    blocks = re.findall(r'<OBJECT basetype="disk-group-statistics".*?</OBJECT>', raw, re.DOTALL)
    result = []
    for b in blocks:
        rd_us = int(_get("avg-read-rsp-time", b) or 0)
        wr_us = int(_get("avg-write-rsp-time", b) or 0)
        result.append({
            "host":         host,
            "name":         _get("name", b),
            "iops":         int(_get("iops", b) or 0),
            "bps":          _get("bytes-per-second", b),
            "read_rsp_us":  rd_us,
            "write_rsp_us": wr_us,
        })
    return result


def _fmt_latency(us: int, is_hdd: bool = True) -> str:
    """格式化延遲並加警示標記。HDD: warn >50ms, crit >100ms。SSD: warn >10ms, crit >30ms。"""
    ms = us / 1000
    if is_hdd:
        tag = " 🔴" if us > 100_000 else (" ⚠️" if us > 50_000 else "")
    else:
        tag = " 🔴" if us > 30_000 else (" ⚠️" if us > 10_000 else "")
    return f"{ms:.1f}ms{tag}"


def _ssh_batch(host: str, cmds: list[str]) -> list[str]:
    """單一 SSH session 執行多個指令，回傳各指令輸出 list。避免 ME 連線頻率限制。"""
    import paramiko
    user, pw = _HOST_CREDS.get(host, _DEFAULT_CREDS)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=pw,
                   timeout=15, allow_agent=False, look_for_keys=False)
    results = []
    try:
        for cmd in cmds:
            _, stdout, _ = client.exec_command(cmd)
            results.append(stdout.read().decode("utf-8", errors="replace"))
    finally:
        client.close()
    return results


def get_san_io_report(host: str) -> str:
    """
    綜合 SAN 健康報告：Controller + Disk Group + Volume 統計，含延遲警示。
    用於調查 storage 效能問題時的完整一次性快照。
    單一 SSH session 批次執行，避免 ME 連線頻率限制。
    HDD 閾值：正常 <20ms，WARN >50ms，CRITICAL >100ms
    """
    try:
        raws = _ssh_batch(host, [
            "show system",
            "show controller-statistics",
            "show disk-group-statistics",
            "show volume-statistics",
        ])
        sys_raw, ctrl_raw, dg_raw, vol_raw = raws
    except Exception as e:
        return f"❌ {host} 連線失敗：{e}"

    model = _get("product-id", sys_raw) or "unknown"
    is_hdd = "ME4" in model

    lines = [
        "=" * 58,
        f"  SAN I/O 報告 — {host}  ({model})",
        "=" * 58,
    ]

    # Controller stats
    ctrl_blocks = re.findall(r'<OBJECT basetype="controller-statistics".*?</OBJECT>', ctrl_raw, re.DOTALL)
    if ctrl_blocks:
        lines.append("\n【Controller】")
        for b in ctrl_blocks:
            ctrl_id   = _get("durable-id", b)
            cpu_pct   = int(_get("cpu-load", b) or 0)
            iops      = int(_get("iops", b) or 0)
            bps       = _get("bytes-per-second", b)
            wr_cache  = int(_get("write-cache-used", b) or 0)
            wr_warn   = " ⚠️" if wr_cache >= 95 else ""
            lines.append(f"  {ctrl_id:14s}  CPU={cpu_pct:3d}%  IOPS={iops:6d}  BPS={bps}  WrCache={wr_cache:3d}%{wr_warn}")

    # Disk group stats
    dg_blocks = re.findall(r'<OBJECT basetype="disk-group-statistics".*?</OBJECT>', dg_raw, re.DOTALL)
    if dg_blocks:
        lines.append("\n【Disk Group 延遲】")
        for b in dg_blocks:
            name  = _get("name", b)
            iops  = int(_get("iops", b) or 0)
            rd_us = int(_get("avg-read-rsp-time", b) or 0)
            wr_us = int(_get("avg-write-rsp-time", b) or 0)
            lines.append(f"  {name:12s}  IOPS={iops:6d}  Rd={_fmt_latency(rd_us, is_hdd)}  Wr={_fmt_latency(wr_us, is_hdd)}")

    # Volume stats
    vol_blocks = re.findall(r'<OBJECT basetype="volume-statistics".*?</OBJECT>', vol_raw, re.DOTALL)
    if vol_blocks:
        lines.append("\n【Volume】")
        for b in vol_blocks:
            name  = _get("volume-name", b)
            iops  = int(_get("iops", b) or 0)
            bps   = _get("bytes-per-second", b)
            rd_us = int(_get("avg-read-rsp-time", b) or 0)
            wr_us = int(_get("avg-write-rsp-time", b) or 0)
            lat   = f"  Rd={_fmt_latency(rd_us, is_hdd)}  Wr={_fmt_latency(wr_us, is_hdd)}" if rd_us or wr_us else ""
            lines.append(f"  {name:20s}  IOPS={iops:6d}  BPS={bps}{lat}")

    lines.append("\n" + "=" * 58)
    return "\n".join(lines)


def _fmt_dur(minutes) -> str:
    if minutes is None:
        return ""
    h, m = divmod(minutes, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m"


def replication_report(hours: int = 24) -> str:
    all_data = get_all_hosts(hours=hours)
    lines = ["=" * 58, "  Dell ME 複製狀態報告（全站）", "=" * 58]

    all_runs = dedup_runs(all_data)

    if all_runs:
        lines.append("\n【複製歷程】")
        for set_name, runs in sorted(all_runs.items()):
            lines.append(f"  {set_name}")
            for r in runs:
                icon = "✅" if r["result"] == "OK" else "❌"
                st   = r["start"].strftime("%m/%d %H:%M") if r["start"] else "—"
                end  = r["end"].strftime("%H:%M") if r["end"] else "—"
                dur  = _fmt_dur(r["dur_min"])
                gb   = f"  {r['data_gb']:.1f} GB" if r["data_gb"] else ""
                lines.append(f"    {icon} {r['state']:11s}  {st} → {end}  ({dur}){gb}")

    # 每台詳細狀態
    lines.append("\n【各台狀態】")
    for host in ME_HOSTS:
        d = all_data[host]
        lines.append(f"  {host}")
        if d["error"]:
            lines.append(f"    ❌ 連線失敗：{d['error']}")
            continue
        for p in d["peers"]:
            icon = "✅" if p["status_num"] == 1 else "❌"
            lines.append(f"    {icon} Peer: {p['name']}  ({p['type']})  {p['status']}")
        for r in d["rep_sets"]:
            _, si = _REP_STATUS.get(r["status_num"], ("?", "❓"))
            ri    = _RUN_STATUS.get(r["last_run_num"], "❓")
            last  = r["last_success"].strftime("%m/%d %H:%M") if r["last_success"] else "—"
            lines.append(f"    {si} {r['name']}  {ri}  最後成功:{last}")
        err_evts = [e for e in d["events"] if e["severity"] in ("ERROR", "CRITICAL")]
        for e in err_evts[:2]:
            t = e["time"].strftime("%m/%d %H:%M") if e["time"] else "—"
            lines.append(f"    ⚠️  [{t}] {e['message'][:60]}")

    lines.append("\n" + "=" * 58)
    return "\n".join(lines)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"

    if cmd == "report":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        print(replication_report(hours=hours))

    elif cmd == "sets":
        all_data = get_all_hosts()
        for host in ME_HOSTS:
            d = all_data[host]
            if d["error"]:
                print(f"❌ {host}: {d['error']}")
                continue
            for r in d["rep_sets"]:
                _, icon = _REP_STATUS.get(r["status_num"], ("?", "❓"))
                run     = _RUN_STATUS.get(r["last_run_num"], "❓")
                last    = r["last_success"].strftime("%Y-%m-%d %H:%M") if r["last_success"] else "—"
                print(f"{icon} {host}  {r['name']:25s}  {run}  last={last}")

    elif cmd == "events":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        all_data = get_all_hosts(hours=hours)
        for host in ME_HOSTS:
            for e in all_data[host]["events"]:
                t = e["time"].strftime("%m/%d %H:%M") if e["time"] else "—"
                print(f"[{t}] {host}  {e['severity']:15s} {e['message'][:70]}")

    elif cmd == "disk-groups":
        for host in ME_HOSTS:
            try:
                dgs = get_disk_groups(host)
            except Exception as e:
                print(f"❌ {host}: {e}")
                continue
            for dg in dgs:
                job_str = f"  [{dg['job']} {dg['job_pct']}]" if dg["job"] else ""
                print(f"{host}  {dg['name']:12s}  {dg['raid']:6s}  {dg['status']:10s}  "
                      f"{dg['size_gb']:.0f}GB / free {dg['free_gb']:.0f}GB{job_str}")

    elif cmd == "inventory":
        for info in get_all_system_info():
            if "error" in info:
                print(f"❌ {info['host']}: {info['error']}")
                continue
            sizes = "+".join(f"{s}GB" for s in info.get("sizes_gb", []))
            arch  = ", ".join(f"{k}×{v}" for k, v in info.get("arch", {}).items())
            print(f"{info['host']}  {info['model']:8s}  {info['total']} disks ({arch})  {sizes}")
            for model, cnt in info.get("models", {}).items():
                print(f"    {model} × {cnt}")

    elif cmd == "ctrl-stats":
        host = sys.argv[2] if len(sys.argv) > 2 else ME_HOSTS[0]
        for c in get_controller_stats(host):
            wr_warn = " ⚠️" if c["wr_cache_pct"] >= 95 else ""
            print(f"{c['controller']:14s}  CPU={c['cpu_pct']:3d}%  IOPS={c['iops']:6d}"
                  f"  BPS={c['bps']:12s}  WrCache={c['wr_cache_pct']:3d}%{wr_warn}")

    elif cmd == "vol-stats":
        host = sys.argv[2] if len(sys.argv) > 2 else ME_HOSTS[0]
        for v in get_volume_stats(host):
            rd_fmt = _fmt_latency(v["read_rsp_us"])
            wr_fmt = _fmt_latency(v["write_rsp_us"])
            print(f"{v['volume']:20s}  IOPS={v['iops']:6d}  BPS={v['bps']:12s}"
                  f"  Rd={rd_fmt}  Wr={wr_fmt}")

    elif cmd == "io":
        host = sys.argv[2] if len(sys.argv) > 2 else ME_HOSTS[0]
        print(f"=== {host} Controller Stats ===")
        for c in get_controller_stats(host):
            print(f"  {c['controller']:14s}  CPU={c['cpu_pct']}%  IOPS={c['iops']}"
                  f"  BPS={c['bps']}  WrCache={c['wr_cache_pct']}%"
                  f"  RdHit={c['rd_hit_pct']:.1f}%  WrHit={c['wr_hit_pct']:.1f}%")
        print(f"\n=== {host} Volume Stats ===")
        for v in get_volume_stats(host):
            print(f"  {v['volume']:20s}  IOPS={v['iops']}  BPS={v['bps']}"
                  f"  Rd={v['read_rsp_us']//1000}ms  Wr={v['write_rsp_us']//1000}ms"
                  f"  RdHit={v['rd_hit_pct']:.1f}%  WrHit={v['wr_hit_pct']:.1f}%")

    elif cmd == "dg-stats":
        # disk group latency — 調查 storage 效能問題時優先執行
        host = sys.argv[2] if len(sys.argv) > 2 else ME_HOSTS[0]
        for dg in get_dg_stats(host):
            rd_ms = dg["read_rsp_us"] / 1000
            wr_ms = dg["write_rsp_us"] / 1000
            rd_warn = " 🔴" if dg["read_rsp_us"] > 100_000 else (" ⚠️" if dg["read_rsp_us"] > 50_000 else "")
            wr_warn = " 🔴" if dg["write_rsp_us"] > 100_000 else (" ⚠️" if dg["write_rsp_us"] > 50_000 else "")
            print(f"{host}  {dg['name']:12s}  IOPS={dg['iops']:6d}  "
                  f"Rd={rd_ms:.1f}ms{rd_warn}  Wr={wr_ms:.1f}ms{wr_warn}")

    elif cmd == "san-report":
        # 完整 SAN 健康快照（controller + DG latency + volume latency）
        hosts = sys.argv[2:] if len(sys.argv) > 2 else ME_HOSTS
        for h in hosts:
            print(get_san_io_report(h))
            print()

    else:
        print(f"Unknown command: {cmd}")
        print("Commands: report, sets, events, disk-groups, inventory, ctrl-stats, vol-stats, io, dg-stats, san-report")
