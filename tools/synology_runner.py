"""Synology DSM API client — Active Backup for Business 備份狀態、監視器攝影機、磁碟健康。"""

import json
import os
import ssl
import urllib.request
import urllib.parse
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

SYNO_HOST   = os.getenv("SYNOLOGY_HOST", "10.11.8.1")
SYNO_PORT   = os.getenv("SYNOLOGY_PORT", "5000")
SYNO_SCHEME = os.getenv("SYNOLOGY_SCHEME", "http")  # TODO: DSM 啟 HTTPS 後改 https + 5001
SYNO_USER   = os.getenv("SYNOLOGY_USER", "infra_ldap")
SYNO_PASS   = _secret("SYNOLOGY_PASS")

_BASE = f"{SYNO_SCHEME}://{SYNO_HOST}:{SYNO_PORT}/webapi/entry.cgi"

# 走 HTTPS 時跳過自簽憑證驗證（與 ppdm/wazuh/fortigate 一致）
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_TZ8  = timezone(timedelta(hours=8))

# version.status 已知值
_VER_STATUS = {3: "✅", 4: "❌", 5: "❌", 6: "⚠️", 7: "⚠️"}


def _post(params: dict) -> dict:
    data = urllib.parse.urlencode(params).encode()
    req  = urllib.request.Request(_BASE, data=data)
    try:
        res = urllib.request.urlopen(req, context=_CTX, timeout=15)
        return json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Synology API → HTTP {e.code}: {e.read().decode()[:200]}")


def login() -> str:
    return login_host(SYNO_HOST)


def logout(sid: str):
    logout_host(SYNO_HOST, sid)


@contextmanager
def _session():
    """建立主機 DSM 連線，離開 with 區塊時自動 logout（含例外狀況）。"""
    sid = login()
    try:
        yield sid
    finally:
        logout(sid)


# ── 多主機通用底層 ─────────────────────────────────────────

def _call(host: str, params: dict) -> dict:
    """對任意 NAS host 發 POST 請求（DSM auth 需要 POST；Storage API 接受 POST）。"""
    base = f"{SYNO_SCHEME}://{host}:{SYNO_PORT}/webapi/entry.cgi"
    body = urllib.parse.urlencode(params).encode()
    req  = urllib.request.Request(base, data=body)
    res  = urllib.request.urlopen(req, context=_CTX, timeout=15)
    data = json.loads(res.read())
    if not data.get("success"):
        code = (data.get("error") or {}).get("code", "?")
        raise RuntimeError(
            f"DSM {host} error {code}: {params.get('api','')}/{params.get('method','')}"
        )
    return data.get("data") or {}


def login_host(host: str) -> str:
    data = _call(host, {
        "api": "SYNO.API.Auth", "method": "login", "version": "7",
        "account": SYNO_USER, "passwd": SYNO_PASS,
    })
    return data["sid"]


def logout_host(host: str, sid: str):
    try:
        _call(host, {"api": "SYNO.API.Auth", "method": "logout", "version": "1", "_sid": sid})
    except Exception:
        pass


# ── 磁碟區與磁碟健康 ──────────────────────────────────────

def get_volumes(host: str, sid: str) -> list:
    """磁碟區清單（容量、使用率、狀態）。"""
    data = _call(host, {
        "api": "SYNO.Storage.CGI.Volume", "version": 1, "method": "list", "_sid": sid,
    })
    result = []
    for v in data.get("volumes", []):
        used  = v.get("used_size",  0) or 0
        total = v.get("total_size", 0) or 0
        util  = round(used / total * 100, 1) if total else 0
        result.append({
            "id":       v.get("id", ""),
            "status":   v.get("status", ""),   # normal / degraded / crashed / syncing
            "fs_type":  v.get("fs_type", ""),
            "used_tb":  round(used  / 1024**4, 2),
            "total_tb": round(total / 1024**4, 2),
            "util":     util,
        })
    return result


def get_disks(host: str, sid: str) -> list:
    """磁碟清單（型號、健康、溫度）。"""
    data = _call(host, {
        "api": "SYNO.Storage.CGI.Disk", "version": 1, "method": "list", "_sid": sid,
    })
    result = []
    for d in data.get("disks", []):
        result.append({
            "slot":   d.get("slot_number", ""),
            "model":  d.get("model", ""),
            "status": d.get("status", ""),       # normal / warning / critical / not_installed
            "temp":   d.get("temp", None),
            "smart":  d.get("smart_status", ""), # normal / failing
        })
    return result


def get_system_info(host: str, sid: str) -> dict:
    """DSM 版本、機型、uptime、溫度。"""
    try:
        data = _call(host, {
            "api": "SYNO.DSM.Info", "version": "2", "method": "getinfo", "_sid": sid,
        })
        uptime_sec = data.get("uptime", 0) or 0
        d, rem     = divmod(uptime_sec, 86400)
        h, _       = divmod(rem, 3600)
        return {
            "version":      data.get("version_string", data.get("version", "")),
            "model":        data.get("model", ""),
            "ram_mb":       data.get("ram", 0),
            "uptime_sec":   uptime_sec,
            "uptime_str":   f"{d}d {h}h" if d else f"{h}h",
            "temp":         data.get("temperature"),
            "temp_warn":    data.get("temperature_warn", False),
        }
    except Exception:
        return {}


def get_abb_status_host(host: str, sid: str) -> list:
    """取得 ABB 備份任務狀態（若未安裝 ABB 則回傳空 list）。"""
    try:
        r = _call(host, {
            "api": "SYNO.ActiveBackup.Task", "method": "list", "version": "1", "_sid": sid,
        })
        tasks = r.get("tasks", [])
    except Exception:
        return []

    results = []
    for t in tasks:
        tid     = t["task_id"]
        running = False

        # pid > 0 表示 job 正在執行
        prog = t.get("progress") or {}
        if prog.get("pid", 0) > 0:
            running = True

        # 取版本清單，找最後一筆「已完成」的版本（time_end > 0）
        last_st, last_dt = None, None
        try:
            vr   = _call(host, {
                "api": "SYNO.ActiveBackup.Version", "method": "list",
                "version": "1", "task_id": str(tid), "_sid": sid,
            })
            vers = vr.get("versions", [])
            # 過濾出已完成的（time_end > 0）
            done = [v for v in vers if v.get("time_end", 0) > 0]
            ver  = done[-1] if done else None
        except Exception:
            ver  = None

        if ver:
            te      = ver.get("time_end", 0)
            last_dt = datetime.fromtimestamp(te, tz=_TZ8).strftime("%m/%d %H:%M") if te else None
            last_st = ver.get("status")   # 3=ok 4/5=fail 6/7=warn

        results.append({
            "name":        t.get("task_name", "?"),
            "last_status": last_st,
            "last_time":   last_dt,
            "running":     running,
        })
    return results


# ── Dashboard 卡片 ─────────────────────────────────────────

def get_replication_tasks(host: str, sid: str) -> list:
    """
    取得 Snapshot Replication 任務清單（API 路徑）。
    前提：DSM > 使用者 > infra.ro > 應用程式 > 啟用 Snapshot Replication。
    回傳 [{name, status, last_time, target}]
    """
    # 嘗試兩個已知 API；version 1 & 2 皆試
    data = {}
    for api, method, ver in [
        ("SYNO.Btrfs.Replica",      "list", "1"),
        ("SYNO.Btrfs.Replica.Core", "list", "1"),
        ("SYNO.Replica.Share",      "list", "1"),
    ]:
        try:
            data = _call(host, {"api": api, "method": method, "version": ver, "_sid": sid})
            if data:
                break
        except Exception:
            continue

    tasks = data.get("tasks") or data.get("replicas") or data.get("shares") or []
    result = []
    for t in tasks:
        name    = t.get("name") or t.get("task_name") or t.get("replica_name", "?")
        target  = t.get("target_host") or t.get("dest") or ""
        last_ts = t.get("last_finish_time") or t.get("finish_time") or 0
        last_dt = datetime.fromtimestamp(last_ts, tz=_TZ8).strftime("%m/%d %H:%M") if last_ts else None
        raw_st  = t.get("status") or t.get("last_status") or ""

        if isinstance(raw_st, int):
            status = {0: "ok", 1: "running", 2: "error"}.get(raw_st, "unknown")
        else:
            s = str(raw_st).lower()
            if "run" in s or "progress" in s:
                status = "running"
            elif "error" in s or "fail" in s:
                status = "error"
            elif "warn" in s:
                status = "warn"
            elif "success" in s or "finish" in s or s == "0":
                status = "ok"
            else:
                status = "unknown"

        result.append({"name": name, "status": status, "last_time": last_dt,
                        "target": target, "raw": raw_st})
    return result



def get_nas_card(host: str, label: str) -> dict:
    """
    回傳單台 NAS 摘要卡片。各資料源獨立 try，不因一項失敗影響其他。
    {label, host, status, volumes, disks, info, abb_tasks, errors}
    status: ok / warn / error
    """
    try:
        sid = login_host(host)
    except Exception as e:
        return {
            "label": label, "host": host, "status": "error",
            "errors": [f"登入失敗：{e}"],
            "volumes": [], "disks": [], "info": {}, "abb_tasks": [],
        }

    errors, volumes, disks, info, abb_tasks, repl_tasks = [], [], [], {}, [], []
    repl_no_perm = False
    try:
        try:
            volumes = get_volumes(host, sid)
        except Exception as e:
            errors.append(f"Volume API：{e}")

        try:
            disks = get_disks(host, sid)
        except Exception as e:
            errors.append(f"Disk API：{e}")

        try:
            info = get_system_info(host, sid)
        except Exception as e:
            errors.append(f"System API：{e}")

        try:
            abb_tasks = get_abb_status_host(host, sid)
        except Exception as e:
            errors.append(f"ABB API：{e}")

        try:
            repl_tasks = get_replication_tasks(host, sid)
        except Exception as e:
            if "105" in str(e):
                repl_no_perm = True   # 需要開放 Snapshot Replication 應用程式權限
            else:
                errors.append(f"Replication API：{e}")
    finally:
        logout_host(host, sid)

    # 區分 permission error（預期）vs 真正錯誤
    perm_errs = [e for e in errors if "error 10" in e]  # 102/103/105 皆為權限/不存在
    real_errs = [e for e in errors if e not in perm_errs]
    no_storage_perm = bool(perm_errs) and not volumes and not disks

    # 狀態判斷
    status = "ok"
    bad_vol  = [v for v in volumes if v["status"] not in ("normal", "")]
    failing  = [d for d in disks   if d["smart"]  == "failing"]
    bad_disk = [d for d in disks   if d["status"] not in ("normal", "not_installed", "")]
    full_vol = [v for v in volumes if v["util"] >= 90]
    warn_vol = [v for v in volumes if 75 <= v["util"] < 90]
    # status 4/5 = 失敗；6/7 = 警告；0/None = 從未執行，不計入
    abb_err  = [t for t in abb_tasks if t["last_status"] in (4, 5)]
    abb_warn = [t for t in abb_tasks if t["last_status"] in (6, 7)]

    if bad_vol or failing or real_errs:
        status = "error"
    elif bad_disk or full_vol or warn_vol or abb_err or abb_warn:
        status = "warn"
    elif info.get("temp_warn"):
        status = "warn"

    return {
        "label":           label,
        "host":            host,
        "status":          status,
        "volumes":         volumes,
        "disks":           disks,
        "info":            info,
        "abb_tasks":       abb_tasks,
        "repl_tasks":      repl_tasks,
        "repl_no_perm":    repl_no_perm,
        "errors":          real_errs,
        "no_storage_perm": no_storage_perm,
    }


def get_nas_list() -> list:
    """從 inventory.yaml 取出 synology: true 的主機。"""
    inv = yaml.safe_load((ROOT / "inventory.yaml").read_text())
    return [
        {"label": h["label"], "host": h["ip"]}
        for h in inv.get("dashboard_servers", [])
        if h.get("synology")
    ]


# ── Active Backup for Business ────────────────────────────────

def get_tasks(sid: str) -> list:
    r = _post({"api": "SYNO.ActiveBackup.Task", "method": "list", "version": "1", "_sid": sid})
    return r.get("data", {}).get("tasks", [])


def get_latest_version(sid: str, task_id: int) -> Optional[dict]:
    """取得任務最新一筆備份版本（含 status, time_end）。"""
    r = _post({"api": "SYNO.ActiveBackup.Version", "method": "list", "version": "1",
               "task_id": str(task_id), "_sid": sid})
    vers = r.get("data", {}).get("versions", [])
    return vers[-1] if vers else None


def get_backup_status(sid: str) -> list:
    """
    回傳每個任務的備份摘要：
      task_id, name, last_time (datetime|None), last_status (int|None),
      next_time (datetime|None), is_scheduled (bool)
    並行抓取各任務的最新版本以節省時間。
    """
    tasks = get_tasks(sid)

    def _fetch(t):
        tid  = t["task_id"]
        name = t.get("task_name", "?")
        next_ts  = t.get("next_trigger_time", 0)
        is_sched = next_ts > 0
        next_dt  = datetime.fromtimestamp(next_ts, tz=_TZ8) if is_sched else None

        ver = get_latest_version(sid, tid)
        if ver:
            te      = ver.get("time_end", 0)
            last_dt = datetime.fromtimestamp(te, tz=_TZ8) if te else None
            last_st = ver.get("status")
        else:
            last_dt = None
            last_st = None

        return {
            "task_id":     tid,
            "name":        name,
            "last_time":   last_dt,
            "last_status": last_st,
            "next_time":   next_dt,
            "is_scheduled": is_sched,
        }

    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(_fetch, t): t["task_id"] for t in tasks}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                results[r["task_id"]] = r
            except Exception:
                tid = futs[fut]
                results[tid] = {"task_id": tid, "name": "?", "last_time": None,
                                "last_status": None, "next_time": None, "is_scheduled": False}

    return [results[t["task_id"]] for t in tasks]


# ── Surveillance Station ──────────────────────────────────────

def get_cameras(sid: str) -> list:
    """取得所有監視器攝影機狀態。"""
    r = _post({"api": "SYNO.SurveillanceStation.Camera", "method": "List", "version": "9",
               "_sid": sid})
    return (r.get("data") or {}).get("cameras", [])


# ── 報告 ──────────────────────────────────────────────────────

def _fmt_dt(dt: Optional[datetime], default="—") -> str:
    return dt.strftime("%m/%d %H:%M") if dt else default


def _status_icon(st: Optional[int]) -> str:
    if st is None:
        return "⬜"
    return _VER_STATUS.get(st, f"⚠️({st})")


def backup_report() -> str:
    with _session() as sid:
        backups = get_backup_status(sid)
        cameras = get_cameras(sid)

    lines = ["=" * 55, "  Synology ABB 備份 / 監視器報告", "=" * 55]

    # 備份任務
    ok    = sum(1 for b in backups if b["last_status"] == 3)
    warn  = sum(1 for b in backups if b["last_status"] not in (3, None))
    no_bk = sum(1 for b in backups if b["last_status"] is None)
    lines.append(f"\n【備份任務】共 {len(backups)} 個   ✅{ok}  ⚠️{warn}  ⬜{no_bk}")

    # 最近30天內有備份的
    now = datetime.now(tz=_TZ8)
    recent_cutoff = now - timedelta(days=30)

    lines.append("\n  近期備份：")
    for b in backups:
        lt = b["last_time"]
        if lt and lt >= recent_cutoff:
            icon = _status_icon(b["last_status"])
            ns   = _fmt_dt(b["next_time"], "停用")
            lines.append(f"  {icon} {b['name'][:30]:30s}  最後:{_fmt_dt(lt)}  下次:{ns}")

    # 超過30天未備份（且有排程）
    stale = [b for b in backups if b["is_scheduled"] and (b["last_time"] is None or b["last_time"] < recent_cutoff)]
    if stale:
        lines.append("\n  ⚠️ 超過30天未備份（仍有排程）：")
        for b in stale:
            lines.append(f"    {b['name'][:40]}  最後:{_fmt_dt(b['last_time'],'從未')}")

    # 監視器
    cam_ok   = sum(1 for c in cameras if c.get("status") == 1)
    cam_warn = len(cameras) - cam_ok
    lines.append(f"\n【監視器】共 {len(cameras)} 台   ✅正常:{cam_ok}  ⚠️異常:{cam_warn}")
    for c in cameras:
        st   = c.get("status", -1)
        icon = "✅" if st == 1 else "❌"
        name = c.get("name") or c.get("newName") or "Unknown"
        ip   = (c.get("ip") or "") + (":" + str(c.get("port","")) if c.get("port") else "")
        lines.append(f"  {icon} {name[:30]:30s}  {ip}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"

    if cmd == "report":
        print(backup_report())

    elif cmd == "tasks":
        with _session() as sid:
            backups = get_backup_status(sid)
        for b in backups:
            icon = _status_icon(b["last_status"])
            ns   = _fmt_dt(b["next_time"], "停用")
            print(f"{icon} [{b['task_id']:2d}] {b['name'][:30]:30s}  最後:{_fmt_dt(b['last_time'])}  下次:{ns}")

    elif cmd == "cameras":
        with _session() as sid:
            cameras = get_cameras(sid)
        for c in cameras:
            st   = c.get("status", -1)
            icon = "✅" if st == 1 else "❌"
            name = c.get("name") or c.get("newName") or "Unknown"
            print(f"{icon} {name}")

    else:
        print(f"Unknown command: {cmd}")
