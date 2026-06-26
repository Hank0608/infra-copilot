"""Zabbix API client — daily health report, problem query, disk-growth analysis."""

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

URL  = os.getenv("ZABBIX_URL")
USER = os.getenv("ZABBIX_USER")
PASS = _secret("ZABBIX_PASS")

SEVERITY = {0: "Not classified", 1: "Information", 2: "Warning",
            3: "Average", 4: "High", 5: "Disaster"}
SEVERITY_EMOJI = {0: "⬜", 1: "🔵", 2: "🟡", 3: "🟠", 4: "🔴", 5: "🚨"}

# (pattern_substring, zh, action, steps)
_TRIGGER_PATTERNS = [
    ("Link down",
     "網路介面斷線",
     "確認設備是否關機或拔線，排查連線問題",
     [("確認設備", "登入交換器確認 port 狀態（show interface）"),
      ("ping 測試", "ping 該 port 對應 IP，確認設備是否在線"),
      ("排除告警", "若設備已永久移除，可在 Zabbix 停用此 trigger")]),

    ("changed to lower speed",
     "網路介面降速",
     "確認線材或 auto-negotiation 問題",
     [("確認協商速度", "登入交換器查看 port 目前協商速度"),
      ("排查線材", "確認 patch cable 品質，必要時替換"),
      ("強制設定", "若反覆發生，考慮設定固定速度避免 auto-negotiation 問題")]),

    ("read/write request responses are too high",
     "磁碟 I/O 延遲過高",
     "確認磁碟 I/O 負載，排查是否有異常大量讀寫",
     [("查看 I/O", "Linux: iostat -x 1 5 或 iotop -ao"),
      ("確認高 I/O 程序", "lsof +D / 或 ps aux | sort -k8 -rn | head"),
      ("VM 層確認", "若為 VM，登入 vCenter 確認 Datastore Latency")]),

    ("write request responses are too high",
     "磁碟寫入延遲過高",
     "確認磁碟寫入效能",
     [("Windows 效能監視器", "perfmon → Disk Write Latency"),
      ("確認來源程序", "Resource Monitor → Disk tab 確認高 I/O 程序"),
      ("VM 層確認", "vCenter → Datastore → Monitor → Performance")]),

    ("read request responses are too high",
     "磁碟讀取延遲過高",
     "確認磁碟讀取效能",
     [("Windows 效能監視器", "perfmon → Disk Read Latency"),
      ("確認來源程序", "Resource Monitor → Disk tab 確認高 I/O 程序"),
      ("VM 層確認", "vCenter → Datastore → Monitor → Performance")]),

    ("space is low",
     "磁碟空間不足",
     "清理磁碟空間或申請擴充",
     [("確認大型目錄", "Linux: du -sh /* | sort -rh | head   Windows: WinDirStat"),
      ("清理 log/temp", "清除 /var/log、%TEMP%、舊備份檔案"),
      ("擴充", "若無法清理，在 vCenter 擴充 VM disk 後執行 resize")]),

    ("housekeeper processes over 75%",
     "Zabbix Housekeeper 負載過高",
     "調整 Housekeeper 設定或縮短資料保留天數",
     [("查看設定", "Administration → General → Housekeeper"),
      ("縮短保留", "降低 History / Trend 保留天數"),
      ("確認 DB 大小", "檢查 Zabbix DB 是否過大，必要時手動清理 history 表")]),

    ("unavailable",
     "主機不可達",
     "確認主機與 Zabbix Agent 狀態",
     [("ping 確認", "ping 主機 IP，確認網路連通"),
      ("Agent 狀態", "systemctl status zabbix-agent 或 zabbix-agent2"),
      ("防火牆", "確認 Zabbix Server → Host 的 10050 port 未被封鎖")]),

    ("high memory utilization",
     "記憶體使用率過高",
     "確認記憶體使用來源，必要時擴充",
     [("確認程序", "Linux: free -h && top   Windows: tasklist /v"),
      ("排查洩漏", "確認是否有程序記憶體持續增長"),
      ("擴充", "若確認需求，在 vCenter 調整 VM 記憶體")]),

    ("cpu utilization",
     "CPU 使用率過高",
     "確認 CPU 使用來源",
     [("確認程序", "Linux: top -c   Windows: tasklist /v | sort"),
      ("排查異常", "確認是否有意外的高 CPU 程序或排程任務"),
      ("調整", "若為正常業務負載，評估是否需要擴充 vCPU")]),
]


def get_trigger_advice(trigger_name: str):
    """根據 trigger 名稱回傳 (zh, action, steps)，找不到回傳 None。"""
    name_lower = trigger_name.lower()
    for pattern, zh, action, steps in _TRIGGER_PATTERNS:
        if pattern.lower() in name_lower:
            return zh, action, steps
    return None


def _call(method: str, params: dict, token: str = None, timeout: int = 30, retries: int = 2) -> dict:
    """Zabbix JSON-RPC. 對 transient 網路錯誤自動 retry（1.5^n 秒 backoff）。"""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode()

    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(URL, data=data, headers=headers)
            res = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
            if "error" in res:
                raise RuntimeError(res["error"]["data"])  # 邏輯錯誤不 retry
            return res["result"]
        except (socket.timeout, urllib.error.URLError, TimeoutError) as e:
            last_err = e
            if attempt < retries:
                time.sleep(1.5 ** attempt)   # 1s → 1.5s → 2.25s
                continue
            raise RuntimeError(f"Zabbix {method} failed after {retries+1} tries: {e}")


def login() -> str:
    return _call("user.login", {"username": USER, "password": PASS})


def logout(token: str):
    _call("user.logout", {}, token)


def _host_status(ifaces: list, active_available: str = None) -> tuple[str, str]:
    """依 interface availability 判斷 host 狀態，回傳 (status, error)。"""
    avail_vals = [i["available"] for i in ifaces]
    if "2" in avail_vals:
        error = next((i.get("error", "") for i in ifaces if i["available"] == "2"), "")
        return "down", error
    if "1" in avail_vals or active_available == "1":
        return "up", ""
    return "unknown", ""


def get_problems(token: str, min_severity: int = 2, days: int = 30) -> list:
    problems = _call("problem.get", {
        "output": ["eventid", "name", "severity", "clock", "acknowledged", "objectid"],
        "severities": list(range(min_severity, 6)),
        "suppressed": False,
        "recent": True,
        "time_from": int(time.time()) - days * 86400,
        "sortfield": ["eventid"],
        "sortorder": "DESC",
        "limit": 200,
    }, token)

    # 取得每個 trigger 對應的主機名稱
    if problems:
        trigger_ids = [p["objectid"] for p in problems]
        triggers = _call("trigger.get", {
            "output": ["triggerid"],
            "selectHosts": ["hostid", "name"],
            "triggerids": trigger_ids,
        }, token)
        trigger_map = {t["triggerid"]: t.get("hosts", []) for t in triggers}
        for p in problems:
            p["hosts"] = trigger_map.get(p["objectid"], [])

    return problems


def get_all_host_data(token: str) -> dict:
    """
    一次查詢所有主機狀態 + 問題，回傳兩個查找表供 dashboard 使用：
      by_name: {hostname_lower → record}
      by_ip:   {ip            → record}
    record: {hostid, name, status, error, problems: [{name, severity, ack}]}
    """
    hosts = _call("host.get", {
        "output":           ["hostid", "name", "active_available"],
        "selectInterfaces": ["available", "error", "type", "ip"],
        "monitored_hosts":  True,
    }, token)

    problems = get_problems(token, min_severity=2)
    prob_by_hid: dict = {}
    for p in problems:
        for h in p.get("hosts", []):
            prob_by_hid.setdefault(h["hostid"], []).append(p)

    by_name: dict = {}
    by_ip:   dict = {}

    for h in hosts:
        ifaces = h.get("interfaces", [])
        status, error = _host_status(ifaces, h.get("active_available"))

        record = {
            "hostid":   h["hostid"],
            "name":     h["name"],
            "status":   status,
            "error":    error,
            "problems": [{
                "name":     p["name"],
                "severity": int(p["severity"]),
                "ack":      p.get("acknowledged") == "1",
            } for p in prob_by_hid.get(h["hostid"], [])],
        }

        by_name[h["name"].lower()] = record
        for iface in ifaces:
            ip = (iface.get("ip") or "").strip()
            if ip and ip != "127.0.0.1":
                by_ip[ip] = record

    return {"by_name": by_name, "by_ip": by_ip}


def get_host_detail(host_name: str, token: str) -> dict:
    """取得單一 host 的詳細狀態與 Problem 列表，供 detail_zabbix 頁使用。"""
    hosts = _call("host.get", {
        "search":           {"name": host_name},
        "output":           ["hostid", "name", "active_available"],
        "selectInterfaces": ["available", "error", "type", "ip", "useip", "dns"],
        "monitored_hosts":  True,
    }, token)
    if not hosts:
        raise ValueError(f"找不到 Zabbix host: {host_name}")
    host   = hosts[0]
    hostid = host["hostid"]

    ifaces = host.get("interfaces", [])
    status, error = _host_status(ifaces, host.get("active_available"))

    problems_raw = _call("problem.get", {
        "output":    ["eventid", "name", "severity", "clock", "acknowledged"],
        "hostids":   [hostid],
        "suppressed": False,
        "recent":    True,
        "time_from": int(time.time()) - 30 * 86400,
        "sortfield": ["eventid"],
        "sortorder": "DESC",
    }, token)

    now = int(time.time())
    problems = []
    for p in problems_raw:
        age = now - int(p["clock"])
        if age < 3600:
            age_str = f"{age // 60}m 前"
        elif age < 86400:
            h, m = divmod(age // 60, 60)
            age_str = f"{h}h {m}m 前"
        else:
            age_str = f"{age // 86400}d 前"
        advice = get_trigger_advice(p["name"])
        problems.append({
            "name":     p["name"],
            "severity": int(p["severity"]),
            "ack":      p.get("acknowledged") == "1",
            "ts":       datetime.fromtimestamp(int(p["clock"]),
                            tz=timezone(timedelta(hours=8))).strftime("%m-%d %H:%M"),
            "age_str":  age_str,
            "zh":       advice[0] if advice else None,
            "action":   advice[1] if advice else None,
            "steps":    advice[2] if advice else [],
        })

    return {
        "name":       host["name"],
        "status":     status,
        "error":      error,
        "interfaces": ifaces,
        "problems":   problems,
    }


def get_host_availability(token: str) -> dict:
    hosts = _call("host.get", {
        "output": ["hostid", "name", "active_available"],
        "selectInterfaces": ["available", "error", "type"],
        "monitored_hosts": True,
        "sortfield": "name",
    }, token)

    up, down, unknown = [], [], []
    for h in hosts:
        status, error = _host_status(h.get("interfaces", []), h.get("active_available"))
        if status == "down":
            h["_error"] = error
            down.append(h)
        elif status == "up":
            up.append(h)
        else:
            unknown.append(h)

    return {"total": len(hosts), "up": up, "down": down, "unknown": unknown}


# ── Web scenario 監控 ─────────────────────────────────────

def get_web_scenarios(hostname: str, token: str = None) -> list:
    """
    查詢指定 host 底下所有 Web scenario 的設定與目前狀態。
    回傳 [{name, enabled, delay, steps: [{name, url, timeout, required,
           status_codes, last_rspcode, last_time}],
           last_fail, last_error, last_clock}]
    last_fail: 0 = 正常，非 0 = 第幾步失敗；None = 尚無資料。
    """
    own = token is None
    if own:
        token = login()
    try:
        host = find_host(hostname, token)
        if not host:
            raise ValueError(f"找不到 host: {hostname}")

        scenarios = _call("httptest.get", {
            "hostids":     [host["hostid"]],
            "output":      ["httptestid", "name", "delay", "status", "retries"],
            "selectSteps": ["name", "no", "url", "timeout", "required", "status_codes"],
        }, token)
        if not scenarios:
            return []

        items = _call("item.get", {
            "hostids":  [host["hostid"]],
            "webitems": True,
            "search":   {"key_": "web.test."},
            "output":   ["key_", "lastvalue", "lastclock"],
        }, token)
        item_by_key = {i["key_"]: i for i in items}

        def _last(key):
            """key 完全比對；用於 fail/error（無額外參數）。"""
            i = item_by_key.get(key)
            return i["lastvalue"] if i and i["lastvalue"] != "" else None

        def _last_prefix(prefix):
            """前綴比對；rspcode/time 的 key 可能帶第三個參數（如 ,resp]）。"""
            for i in items:
                if i["key_"].startswith(prefix) and i["lastvalue"] != "":
                    return i["lastvalue"]
            return None

        result = []
        for sc in scenarios:
            name = sc["name"]
            steps = []
            for st in sorted(sc.get("steps", []), key=lambda s: int(s["no"])):
                steps.append({
                    "name":         st["name"],
                    "url":          st["url"],
                    "timeout":      st["timeout"],
                    "required":     st.get("required") or None,
                    "status_codes": st.get("status_codes") or None,
                    "last_rspcode": _last_prefix(f"web.test.rspcode[{name},{st['name']}"),
                    "last_time":    _last_prefix(f"web.test.time[{name},{st['name']}"),
                })

            fail_item = item_by_key.get(f"web.test.fail[{name}]")
            result.append({
                "name":       name,
                "enabled":    sc["status"] == "0",
                "delay":      sc["delay"],
                "retries":    sc.get("retries"),
                "steps":      steps,
                "last_fail":  int(fail_item["lastvalue"]) if fail_item and fail_item["lastvalue"] != "" else None,
                "last_error": _last(f"web.test.error[{name}]"),
                "last_clock": (datetime.fromtimestamp(int(fail_item["lastclock"]), tz=_TZ8)
                               .strftime("%Y-%m-%d %H:%M")
                               if fail_item and fail_item.get("lastclock") not in (None, "0") else None),
            })
        return result
    finally:
        if own:
            logout(token)


def web_scenario_report(hostname: str) -> str:
    """格式化的 Web scenario 設定與現況報告。"""
    scenarios = get_web_scenarios(hostname)
    lines = ["=" * 60, f"  Web Scenario — {hostname}", "=" * 60]

    if not scenarios:
        lines.append("\n  (此 host 沒有設定 Web scenario)")
        return "\n".join(lines)

    for sc in scenarios:
        state = "啟用" if sc["enabled"] else "停用"
        fail = sc["last_fail"]
        if fail is None:
            health = "❓ 尚無資料"
        elif fail == 0:
            health = "✅ 正常"
        else:
            health = f"🔴 失敗（第 {fail} 步，{sc['last_error'] or '無錯誤訊息'}）"
        lines.append(f"\n=== {sc['name']} ({state}, 間隔 {sc['delay']}) ===")
        lines.append(f"狀態: {health}" + (f"　最後檢查: {sc['last_clock']}" if sc["last_clock"] else ""))
        for st in sc["steps"]:
            lines.append(f"  • {st['name']}: {st['url']}")
            lines.append(f"      timeout={st['timeout']}  required={st['required']}  status_codes={st['status_codes']}")
            lines.append(f"      最後 rspcode={st['last_rspcode']}  最後 time={st['last_time']}")
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ── 磁碟成長分析 ──────────────────────────────────────────

_TZ8 = timezone(timedelta(hours=8))
_DISK_KEY_RE = re.compile(r'vfs\.fs(?:\.dependent)?\.size\[([^,]+),(used|total|free|pused)\]')


def get_trends(hostname: str, item_search: str, days: int = 90, token: str = None) -> list:
    """
    拉指定主機某個 item 的 trends 歷史（Zabbix 壓縮後的小時平均）。
    比 history.get 能往前拉更久，適合 30~90 天趨勢分析。

    item_search: item name 關鍵字，例如 "CPU utilization"、"Memory utilization"
    回傳 [{"date": date, "avg": float, "max": float, "min": float}, ...]，依日期排序。
    """
    import datetime, time

    own = token is None
    if own:
        token = login()
    try:
        host = find_host(hostname, token)
        if not host:
            return []

        items = _call("item.get", {
            "hostids": host["hostid"],
            "search":  {"name": item_search},
            "output":  ["itemid", "name"],
        }, token)
        if not items:
            return []

        itemid  = items[0]["itemid"]
        now     = int(time.time())
        results = _call("trend.get", {
            "itemids":   itemid,
            "time_from": now - days * 86400,
            "time_till": now,
            "output":    "extend",
            "sortfield": "clock",
            "sortorder": "ASC",
        }, token)

        by_day = {}
        for t in results:
            d = datetime.datetime.fromtimestamp(int(t["clock"])).date()
            by_day.setdefault(d, []).append({
                "avg": float(t["value_avg"]),
                "max": float(t["value_max"]),
                "min": float(t["value_min"]),
            })

        rows = []
        for d in sorted(by_day):
            hrs = by_day[d]
            rows.append({
                "date": d,
                "avg":  round(sum(h["avg"] for h in hrs) / len(hrs), 2),
                "max":  round(max(h["max"] for h in hrs), 2),
                "min":  round(min(h["min"] for h in hrs), 2),
            })
        return rows
    finally:
        if own:
            logout(token)


def find_host(name: str, token: str = None) -> dict:
    """
    比對 host name，回 {hostid, host, name}；找不到回 None。
    優先回傳完全比對（不分大小寫）的結果；若名稱剛好是別的 host 名稱的子字串
    （例如 "BI" 也會模糊比對到 "Zabbix server"、"BI-clone"），避免誤拿錯的 host。
    完全比對不到時，才退回模糊比對的第一筆。
    """
    own = token is None
    if own:
        token = login()
    try:
        hosts = _call("host.get", {"search": {"name": name},
                                    "output": ["hostid", "host", "name"]}, token)
        if not hosts:
            return None
        exact = [h for h in hosts if h["name"].lower() == name.lower()]
        return exact[0] if exact else hosts[0]
    finally:
        if own:
            logout(token)


def _get_disk_items(hostid: str, token: str) -> dict:
    """回傳 {drive: {used, total, free, pused}} 的 itemid mapping。"""
    items = _call("item.get", {
        "hostids": [hostid],
        "search": {"key_": "vfs.fs"},
        "output": ["itemid", "key_"],
    }, token)
    drives = {}
    for it in items:
        m = _DISK_KEY_RE.match(it["key_"])
        if not m:
            continue
        drive, kind = m.group(1), m.group(2)
        drives.setdefault(drive, {})[kind] = it["itemid"]
    return {d: v for d, v in drives.items() if "used" in v and "total" in v}


def get_disk_growth(hostname: str, days: int = 90) -> dict:
    """
    分析指定 host 在 N 天內的磁碟成長。
    回傳 {host, days, as_of, disks: [{drive, total_gb, used_gb, used_pct, free_gb,
                                       first_dt, first_gb, grow_gb, rate_mb_day,
                                       rate_gb_month, days_to_full, segments, samples}]}
    """
    token = login()
    try:
        host = find_host(hostname, token)
        if not host:
            raise ValueError(f"找不到 host: {hostname}")
        drives = _get_disk_items(host["hostid"], token)
        if not drives:
            raise ValueError(f"host '{hostname}' 沒有 vfs.fs.size items")

        # 一次拿所有 itemid 的 lastvalue（總量會長時間不變，trend 不一定有最新）
        all_ids = [iid for v in drives.values() for iid in v.values()]
        items = _call("item.get", {"itemids": all_ids,
                                    "output": ["itemid", "lastvalue"]}, token)
        last_map = {i["itemid"]: float(i["lastvalue"] or 0) for i in items}

        now = int(time.time())
        as_of = datetime.fromtimestamp(now, tz=_TZ8)

        # 區段觀測點：days, 2/3 days, 1/3 days（dedupe 並去除 0）
        seg_offsets = sorted({days, days * 2 // 3, days // 3}, reverse=True)
        seg_offsets = [o for o in seg_offsets if o > 0]

        result = {"host": host["name"], "days": days, "as_of": as_of, "disks": []}

        for drive in sorted(drives.keys()):
            ids = drives[drive]
            trend = _call("trend.get", {
                "output": ["clock", "value_avg"],
                "itemids": [ids["used"]],
                "time_from": now - days * 86400,
                "time_till": now,
            }, token, timeout=120)
            if not trend:
                continue
            trend.sort(key=lambda x: int(x["clock"]))
            first   = trend[0]
            first_dt = datetime.fromtimestamp(int(first["clock"]), tz=_TZ8)
            actual_days = (now - int(first["clock"])) / 86400
            first_gb = float(first["value_avg"]) / 1024**3
            used_gb  = last_map[ids["used"]]  / 1024**3
            total_gb = last_map[ids["total"]] / 1024**3
            grow_gb  = used_gb - first_gb
            rate     = grow_gb / actual_days if actual_days > 0 else 0
            free_gb  = total_gb - used_gb

            def _avg_near(ts: int, w: int = 86400):
                pts = [float(p["value_avg"]) / 1024**3 for p in trend
                       if abs(int(p["clock"]) - ts) < w]
                return sum(pts) / len(pts) if pts else None

            segments = []
            for off in seg_offsets:
                v = _avg_near(now - off * 86400)
                if v is not None:
                    segments.append({"label": f"-{off}d", "avg_gb": round(v, 2)})
            segments.append({"label": "now", "avg_gb": round(used_gb, 2)})

            result["disks"].append({
                "drive":         drive,
                "total_gb":      round(total_gb, 1),
                "used_gb":       round(used_gb, 1),
                "used_pct":      round(used_gb / total_gb * 100, 1) if total_gb > 0 else 0,
                "free_gb":       round(free_gb, 1),
                "first_dt":      first_dt,
                "first_gb":      round(first_gb, 1),
                "grow_gb":       round(grow_gb, 2),
                "rate_mb_day":   round(rate * 1024, 1),
                "rate_gb_month": round(rate * 30, 2),
                "days_to_full":  round(free_gb / rate, 0) if rate > 0.001 else None,
                "samples":       len(trend),
                "actual_days":   round(actual_days),
                "segments":      segments,
            })
        return result
    finally:
        logout(token)


def disk_growth_report(hostname: str, days: int = 90) -> str:
    """格式化的磁碟成長分析報告。"""
    g = get_disk_growth(hostname, days)
    lines = ["=" * 60,
             f"  磁碟成長分析 — {g['host']}（過去 {days} 天）",
             "=" * 60,
             f"分析時間: {g['as_of'].strftime('%Y-%m-%d %H:%M')}"]

    if not g["disks"]:
        lines.append("\n  (無 trend 資料)")
        return "\n".join(lines)

    for d in g["disks"]:
        lines.append(f"\n=== {d['drive']} ===")
        lines.append(f"磁碟總量    : {d['total_gb']:6.1f} GB")
        lines.append(f"目前用量    : {d['used_gb']:6.1f} GB ({d['used_pct']:.1f}%)   剩餘 {d['free_gb']:.1f} GB")
        lines.append(f"{d['actual_days']} 天前用量 : {d['first_gb']:6.1f} GB")
        lines.append(f"{d['actual_days']} 天淨成長 : {d['grow_gb']:+.2f} GB ({d['rate_mb_day']:+.1f} MB/day, {d['rate_gb_month']:+.2f} GB/月)")
        if d["days_to_full"] is not None:
            full_dt = g["as_of"] + timedelta(days=d["days_to_full"])
            lines.append(f"線性預估    : {d['days_to_full']:.0f} 天後滿 (~{full_dt.strftime('%Y-%m-%d')})")
        else:
            lines.append("線性預估    : 速率近 0 或縮減，不會滿")
        lines.append("區段日均    :")
        prev = None
        for s in d["segments"]:
            diff = f"  Δ {s['avg_gb'] - prev:+6.2f} GB" if prev is not None else ""
            lines.append(f"  {s['label']:>5s}: {s['avg_gb']:6.1f} GB{diff}")
            prev = s["avg_gb"]
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def daily_report() -> str:
    token = login()
    try:
        avail    = get_host_availability(token)
        problems = get_problems(token, min_severity=2)
    finally:
        logout(token)

    lines = ["=" * 55]
    lines.append("  Zabbix 每日健康報告")
    lines.append("=" * 55)

    # 主機存活摘要
    lines.append(f"\n【主機狀態】共 {avail['total']} 台")
    lines.append(f"  ✅ 正常 : {len(avail['up'])} 台")
    if avail["down"]:
        lines.append(f"  ❌ 離線 : {len(avail['down'])} 台")
        for h in avail["down"]:
            err = f" — {h['_error']}" if h.get("_error") else ""
            lines.append(f"      • {h['name']}{err}")
    if avail["unknown"]:
        lines.append(f"  ❓ 未知 : {len(avail['unknown'])} 台")
        for h in avail["unknown"]:
            lines.append(f"      • {h['name']}")

    # 問題清單
    lines.append(f"\n【未解決問題】{len(problems)} 筆（Warning 以上）")
    if not problems:
        lines.append("  🎉 目前無異常")
    else:
        for p in problems:
            sev   = int(p["severity"])
            icon  = SEVERITY_EMOJI.get(sev, "❓")
            label = SEVERITY.get(sev, "?")
            hosts = ", ".join(h["name"] for h in p.get("hosts", []))
            ack   = "（已確認）" if p["acknowledged"] == "1" else ""
            lines.append(f"  {icon} [{label}] {p['name']}{ack}")
            if hosts:
                lines.append(f"      主機：{hosts}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"

    if cmd == "report":
        print(daily_report())
    elif cmd == "disk":
        if len(sys.argv) < 3:
            print("Usage: zabbix_runner.py disk <hostname> [days=90]")
            sys.exit(1)
        host = sys.argv[2]
        days = int(sys.argv[3]) if len(sys.argv) > 3 else 90
        print(disk_growth_report(host, days))
    elif cmd == "web":
        if len(sys.argv) < 3:
            print("Usage: zabbix_runner.py web <hostname>")
            sys.exit(1)
        print(web_scenario_report(sys.argv[2]))
    else:
        print(f"Usage: zabbix_runner.py [report | disk <host> [days] | web <host>]")
        sys.exit(1)
