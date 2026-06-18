"""PPDM (Dell PowerProtect Data Manager) REST API client — 備份作業、資產、告警。"""

import json
import os
import ssl
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

PPDM_HOST = os.getenv("PPDM_HOST", "10.11.1.32")
PPDM_PORT = int(os.getenv("PPDM_PORT", "8443"))
PPDM_USER = os.getenv("PPDM_USER", "infra.ro")
PPDM_PASS = _secret("PPDM_PASS")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_BASE = f"https://{PPDM_HOST}:{PPDM_PORT}/api/v2"

SEVERITY_EMOJI = {"CRITICAL": "🚨", "WARNING": "🟡", "INFO": "🔵", "OK": "✅"}
STATUS_EMOJI   = {"OK": "✅", "FAILED": "❌", "OK_WITH_ERRORS": "🟡", "CANCELED": "⬜"}


def login() -> str:
    data = json.dumps({"username": PPDM_USER, "password": PPDM_PASS}).encode()
    req  = urllib.request.Request(_BASE + "/login", data=data,
                                  headers={"Content-Type": "application/json"})
    res  = urllib.request.urlopen(req, context=_CTX, timeout=10)
    return json.loads(res.read())["access_token"]


def logout(token: str):
    try:
        req = urllib.request.Request(_BASE + "/logout", data=b"",
                                     headers={"Authorization": f"Bearer {token}",
                                              "Content-Type": "application/json"},
                                     method="POST")
        urllib.request.urlopen(req, context=_CTX, timeout=5)
    except Exception:
        pass


def _get(token: str, path: str, params: dict = None) -> dict:
    url = _BASE + path
    if params:
        url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}"
                              for k, v in params.items() if v is not None)
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        res = urllib.request.urlopen(req, context=_CTX, timeout=15)
        return json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"PPDM API {path} → HTTP {e.code}: {e.read().decode()[:200]}")


# ── 備份作業 ──────────────────────────────────────────────

def get_recent_jobs(token: str, hours: int = 24) -> list:
    """取得最近 N 小時內的備份作業（PROTECT JOB）。"""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filt  = urllib.parse.quote(f'classType eq "JOB" and category eq "PROTECT" and createTime gt "{since}"')
    data  = _get(token, f"/activities?pageSize=200&filter={filt}&orderby=createTime+DESC")
    return data.get("content", [])


def get_policy_run(token: str, policy_name: str) -> dict:
    """
    取得指定 Protection Policy 最新一次執行的 group job 及其 per-VM sub-jobs。
    回傳 {"group": {...}, "vms": [...], "ok": int, "total": int}
    """
    filt = urllib.parse.quote('classType eq "JOB_GROUP" and category eq "PROTECT"')
    r    = _get(token, f"/activities?pageSize=50&filter={filt}&orderby=createTime+DESC")
    groups = [j for j in r.get("content", []) if policy_name in j.get("name", "")]
    if not groups:
        return {}
    grp = groups[0]

    filt2 = urllib.parse.quote(f'parentId eq "{grp["id"]}"')
    r2    = _get(token, f"/activities?pageSize=100&filter={filt2}&orderby=createTime+ASC")
    vms   = []
    for j in r2.get("content", []):
        status = (j.get("result") or {}).get("status", "?")
        raw    = j.get("assetName") or j.get("name", "")
        name   = raw.replace("Protecting VM - ", "").strip()
        end    = str(j.get("endTime", ""))[:16].replace("T", " ")
        vms.append({"name": name, "status": status, "end": end, "id": j.get("id", "")})

    ok = sum(1 for v in vms if v["status"] == "OK")
    return {
        "group":   grp,
        "vms":     vms,
        "ok":      ok,
        "failed":  len(vms) - ok,
        "total":   len(vms),
        "start":   str(grp.get("createTime", ""))[:16].replace("T", " "),
        "status":  (grp.get("result") or {}).get("status", "?"),
        "type":    grp.get("name", "").split(" - ")[-1] if " - " in grp.get("name","") else "",
    }


def get_failed_jobs(token: str, limit: int = 20) -> list:
    """取得最近失敗的備份作業。"""
    filt = urllib.parse.quote('classType eq "JOB" and result.status eq "FAILED"')
    data = _get(token, f"/activities?pageSize={limit}&filter={filt}&orderby=createTime+DESC")
    return data.get("content", [])


def get_backup_summary(token: str, hours: int = 24) -> dict:
    """最近 N 小時備份成功/失敗統計。"""
    jobs = get_recent_jobs(token, hours)
    counts = {"ok": 0, "failed": 0, "ok_with_errors": 0, "other": 0, "total": len(jobs)}
    for j in jobs:
        s = (j.get("result") or {}).get("status", "")
        if s == "OK":
            counts["ok"] += 1
        elif s == "FAILED":
            counts["failed"] += 1
        elif s == "OK_WITH_ERRORS":
            counts["ok_with_errors"] += 1
        else:
            counts["other"] += 1
    return counts


# ── 資產 ─────────────────────────────────────────────────

def get_assets(token: str, asset_type: str = None) -> list:
    """取得受保護資產清單。asset_type: VMWARE_VIRTUAL_MACHINE / DR 等"""
    path = "/assets?pageSize=200"
    if asset_type:
        filt = urllib.parse.quote(f'type eq "{asset_type}"')
        path += f"&filter={filt}"
    data = _get(token, path)
    return data.get("content", [])


def get_unprotected_assets(token: str) -> list:
    """取得未受保護的資產。"""
    filt = urllib.parse.quote('protectionStatus eq "UNPROTECTED"')
    data = _get(token, f"/assets?pageSize=200&filter={filt}")
    return data.get("content", [])


# ── 儲存空間 ──────────────────────────────────────────────

def get_storage(token: str) -> list:
    """取得儲存系統（Data Domain）使用狀況。"""
    data = _get(token, "/storage-systems")
    result = []
    for s in data.get("content", []):
        entry = {
            "name":        s.get("name", ""),
            "type":        s.get("type", ""),
            "utilization": round(s.get("capacityUtilization", 0), 1),
            "readiness":   s.get("readiness", ""),
        }
        dd = (s.get("details") or {}).get("dataDomain")
        if dd:
            used_tb  = (dd.get("totalUsed") or 0) / 1024**4
            util     = s.get("capacityUtilization", 0) or 0
            total_tb = (used_tb / (util / 100)) if util > 0 else 0
            entry.update({
                "model":       dd.get("model", ""),
                "version":     dd.get("version", ""),
                "used_tb":     round(used_tb, 1),
                "total_tb":    round(total_tb, 1),
                "compression": round(dd.get("compressionFactor", 0), 1),
            })
        result.append(entry)
    return result


# ── 告警 ─────────────────────────────────────────────────

def get_search_cluster_status(token: str) -> dict:
    """
    回傳 Search cluster 狀態。
    {state, state_detail, total_nodes, failed_nodes, total_assets,
     indexed_assets, last_metadata_sync, disk_used_gb, disk_total_gb, nodes}
    """
    data    = _get(token, "/search-clusters")
    content = data.get("content", [])
    if not content:
        return {"state": "UNKNOWN", "state_detail": "no cluster found"}
    c = content[0]
    s = c.get("summary", {})
    used_gb  = s.get("totalDiskUsage", 0)  / 1024 ** 3
    total_gb = s.get("totalDiskCapacity", 0) / 1024 ** 3
    return {
        "state":              c.get("state"),
        "state_detail":       c.get("stateDetail"),
        "maintenance_mode":   c.get("maintenanceMode", False),
        "total_nodes":        s.get("totalNodes", 0),
        "failed_nodes":       s.get("totalFailed", 0),
        "total_assets":       s.get("totalAssets", 0),
        "indexed_assets":     s.get("totalAssetsIndexed", 0),
        "last_metadata_sync": s.get("lastMetadataSyncTime"),
        "disk_used_gb":       round(used_gb, 1),
        "disk_total_gb":      round(total_gb, 1),
        "nodes":              s.get("nodes", []),
    }


def get_discovery_jobs(token: str, limit: int = 20) -> list:
    """
    回傳 vCenter discovery 相關 jobs（成功 + 失敗）。
    fields: name, status, startTime, endTime, duration, error_reason
    """
    import urllib.parse as _up
    filt = _up.quote('category eq "DISCOVER"')
    path = f"/activities?pageSize={limit}&orderby=startTime+DESC&filter={filt}"
    data = _get(token, path)
    result = []
    for j in data.get("content", []):
        res    = j.get("result", {})
        err    = res.get("error", {})
        result.append({
            "name":         j.get("name"),
            "status":       res.get("status"),
            "start":        j.get("startTime"),
            "end":          j.get("endTime"),
            "duration_sec": round(j.get("duration", 0) / 1000),
            "initiated":    j.get("activityInitiatedType") or "",
            "error_reason": err.get("reason") or (res.get("summaries") or [None])[0],
        })
    return result


def get_alerts(token: str, severity: str = None, limit: int = 50) -> list:
    """取得系統告警。severity: CRITICAL / WARNING / INFO"""
    path = f"/alerts?pageSize={limit}&orderby=postedTime+DESC"
    if severity:
        filt = urllib.parse.quote(f'severity eq "{severity}"')
        path += f"&filter={filt}"
    data = _get(token, path)
    return data.get("content", [])


# ── 報告 ──────────────────────────────────────────────────

def backup_report(hours: int = 24) -> str:
    """備份健康日報（文字版）。"""
    token = login()
    try:
        summary    = get_backup_summary(token, hours)
        jobs       = get_recent_jobs(token, hours)
        storage    = get_storage(token)
        alerts     = get_alerts(token, limit=50)
        unprotected = get_unprotected_assets(token)
    finally:
        logout(token)

    lines = ["=" * 55, "  PPDM 備份健康報告", "=" * 55]

    # 備份摘要
    total = summary["total"]
    ok    = summary["ok"]
    fail  = summary["failed"]
    warn  = summary["ok_with_errors"]
    lines.append(f"\n【備份作業】最近 {hours} 小時，共 {total} 筆")
    lines.append(f"  ✅ 成功        : {ok}")
    if warn:
        lines.append(f"  🟡 含警告      : {warn}")
    if fail:
        lines.append(f"  ❌ 失敗        : {fail}")

    failed_jobs = [j for j in jobs if (j.get("result") or {}).get("status") == "FAILED"]
    if failed_jobs:
        lines.append("\n  失敗作業：")
        for j in failed_jobs[:10]:
            vm = j.get("name", "")
            t  = str(j.get("endTime", ""))[:16].replace("T", " ")
            lines.append(f"    ❌ {vm[:50]:<50} {t}")

    # 儲存空間
    lines.append("\n【儲存空間】")
    for s in storage:
        if s["type"] == "DATA_DOMAIN_SYSTEM":
            util = s["utilization"]
            icon = "🔴" if util >= 85 else ("🟡" if util >= 70 else "✅")
            lines.append(f"  {icon} {s['name']}")
            lines.append(f"     使用：{s.get('used_tb', 0):.1f} TB / {s.get('total_tb', 0):.1f} TB  "
                         f"({util:.1f}%)  壓縮比：{s.get('compression', 0):.1f}x")

    # 未保護資產
    if unprotected:
        lines.append(f"\n【未保護資產】{len(unprotected)} 筆")
        for a in unprotected[:10]:
            lines.append(f"  ⬜ {a.get('name', '')[:50]}")

    # 告警
    crit = [a for a in alerts if a.get("severity") == "CRITICAL"]
    warn_al = [a for a in alerts if a.get("severity") == "WARNING"]
    lines.append(f"\n【系統告警】CRITICAL:{len(crit)}  WARNING:{len(warn_al)}")
    if crit:
        for a in crit[:5]:
            t = str(a.get("postedTime", ""))[:16].replace("T", " ")
            lines.append(f"  🚨 [{t}] {a.get('message','')[:70]}")
    if warn_al:
        for a in warn_al[:5]:
            t = str(a.get("postedTime", ""))[:16].replace("T", " ")
            lines.append(f"  🟡 [{t}] {a.get('message','')[:70]}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


def get_dashboard_card(hours: int = 24) -> dict:
    """
    回傳 dashboard 用的 PPDM 摘要卡片。
    {status, summary, failed_jobs, storage, alerts}
    status: ok / warn / error
    """
    token = login()
    try:
        summary      = get_backup_summary(token, hours)
        all_jobs     = get_recent_jobs(token, hours)
        storage      = get_storage(token)
        crit_alerts  = get_alerts(token, severity="CRITICAL", limit=20)
        warn_alerts  = get_alerts(token, severity="WARNING",  limit=20)
    finally:
        logout(token)

    failed_jobs = [
        {
            "name":    j.get("name", ""),
            "end":     str(j.get("endTime", ""))[:16].replace("T", " "),
            "message": ((j.get("result") or {}).get("error") or {}).get("message", ""),
        }
        for j in all_jobs
        if (j.get("result") or {}).get("status") == "FAILED"
    ][:15]

    warn_jobs = [
        {"name": j.get("name", ""), "end": str(j.get("endTime", ""))[:16].replace("T", " ")}
        for j in all_jobs
        if (j.get("result") or {}).get("status") == "OK_WITH_ERRORS"
    ][:10]

    # 狀態判斷
    max_util = max((s.get("utilization", 0) for s in storage), default=0)
    status = "ok"
    if summary["failed"] > 0 or crit_alerts:
        status = "error"
    elif summary["ok_with_errors"] > 0 or warn_alerts or max_util >= 70:
        status = "warn"

    return {
        "status":      status,
        "summary":     summary,
        "failed_jobs": failed_jobs,
        "warn_jobs":   warn_jobs,
        "storage":     storage,
        "crit_alerts": [{"msg": a.get("message","")[:120], "ts": str(a.get("postedTime",""))[:16].replace("T"," ")} for a in crit_alerts],
        "warn_alerts": [{"msg": a.get("message","")[:120], "ts": str(a.get("postedTime",""))[:16].replace("T"," ")} for a in warn_alerts[:10]],
        "hours":       hours,
    }


def get_detail(hours: int = 24) -> dict:
    """
    回傳 PPDM detail 頁面用的完整資料。
    {summary, failed_jobs, warn_jobs, all_jobs, storage, crit_alerts, warn_alerts,
     unprotected, search_cluster, hours}
    """
    token = login()
    try:
        summary        = get_backup_summary(token, hours)
        all_jobs       = get_recent_jobs(token, hours)
        storage        = get_storage(token)
        crit_alerts    = get_alerts(token, severity="CRITICAL", limit=30)
        warn_alerts    = get_alerts(token, severity="WARNING",  limit=30)
        unprotected    = get_unprotected_assets(token)
        try:
            search_cluster = get_search_cluster_status(token)
        except Exception:
            search_cluster = None
    finally:
        logout(token)

    def _fmt_job(j):
        res = j.get("result") or {}
        err = res.get("error") or {}
        return {
            "name":    j.get("name", ""),
            "status":  res.get("status", "?"),
            "start":   str(j.get("createTime", ""))[:16].replace("T", " "),
            "end":     str(j.get("endTime", ""))[:16].replace("T", " "),
            "message": err.get("message", ""),
        }

    return {
        "summary":       summary,
        "failed_jobs":   [_fmt_job(j) for j in all_jobs if (j.get("result") or {}).get("status") == "FAILED"],
        "warn_jobs":     [_fmt_job(j) for j in all_jobs if (j.get("result") or {}).get("status") == "OK_WITH_ERRORS"],
        "all_jobs":      [_fmt_job(j) for j in all_jobs],
        "storage":       storage,
        "crit_alerts":   [{"msg": a.get("message","")[:200], "ts": str(a.get("postedTime",""))[:16].replace("T"," ")} for a in crit_alerts],
        "warn_alerts":   [{"msg": a.get("message","")[:200], "ts": str(a.get("postedTime",""))[:16].replace("T"," ")} for a in warn_alerts],
        "unprotected":   [{"name": a.get("name",""), "type": a.get("type","")} for a in unprotected],
        "search_cluster": search_cluster,
        "hours":         hours,
    }


if __name__ == "__main__":
    import sys
    token = login()
    cmd   = sys.argv[1] if len(sys.argv) > 1 else "report"

    if cmd == "report":
        logout(token)
        print(backup_report())
    elif cmd == "jobs":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        jobs  = get_recent_jobs(token, hours)
        for j in jobs:
            s    = (j.get("result") or {}).get("status", "?")
            icon = STATUS_EMOJI.get(s, "?")
            t    = str(j.get("endTime", ""))[:16].replace("T", " ")
            print(f"{icon} {j.get('name','')[:60]:<60} {t}")
        logout(token)
    elif cmd == "failed":
        jobs = get_failed_jobs(token)
        for j in jobs:
            t = str(j.get("endTime", ""))[:16].replace("T", " ")
            print(f"❌ {t}  {j.get('name','')}")
        logout(token)
    elif cmd == "storage":
        for s in get_storage(token):
            print(f"{s['name']} ({s['type']})  util={s['utilization']}%  "
                  f"{s.get('used_tb',0):.1f}TB/{s.get('total_tb',0):.1f}TB  "
                  f"compression={s.get('compression',0):.1f}x")
        logout(token)
    elif cmd == "alerts":
        for a in get_alerts(token):
            icon = SEVERITY_EMOJI.get(a.get("severity",""), "?")
            print(f"{icon} {a.get('message','')[:80]}")
        logout(token)
    else:
        logout(token)
        print(f"Unknown command: {cmd}")
