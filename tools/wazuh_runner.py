"""Wazuh REST API client — agent 狀態、SCA 合規、syscollector 查詢。"""

import base64
import json
import os
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

WAZUH_HOST = os.getenv("WAZUH_HOST", "10.200.80.33")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER = os.getenv("WAZUH_USER", "infra.ro")
WAZUH_PASS = _secret("WAZUH_PASS")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_BASE = f"https://{WAZUH_HOST}:{WAZUH_PORT}"

AGENT_STATUS_EMOJI = {
    "active":        "✅",
    "disconnected":  "❌",
    "never_connected": "⬜",
    "pending":       "🔄",
}


def login() -> str:
    """取得 JWT token。"""
    creds = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    req = urllib.request.Request(f"{_BASE}/security/user/authenticate", method="POST")
    req.add_header("Authorization", f"Basic {creds}")
    res = urllib.request.urlopen(req, context=_CTX, timeout=10)
    return json.loads(res.read())["data"]["token"]


def _get(token: str, path: str, params: dict = None) -> dict:
    url = _BASE + path
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        res = urllib.request.urlopen(req, context=_CTX, timeout=15)
        return json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Wazuh API {path} → HTTP {e.code}: {e.read().decode()}")


# ── Agent 查詢 ────────────────────────────────────────────

def get_agents(token: str, status: str = None) -> list:
    """取得所有 agent 清單。status: active/disconnected/never_connected/pending"""
    params = {"limit": 500}
    if status:
        params["status"] = status
    data = _get(token, "/agents", params)
    return data["data"]["affected_items"]


def get_agent_by_name(token: str, name: str) -> dict:
    """依名稱找 agent。"""
    data = _get(token, "/agents", {"name": name, "limit": 5})
    items = data["data"]["affected_items"]
    return items[0] if items else None


def get_agent_summary(token: str) -> dict:
    """取得 agent 狀態統計。"""
    data = _get(token, "/agents/summary/status")
    conn = data["data"].get("connection", {})
    return {
        "total":           conn.get("total", 0),
        "active":          conn.get("active", 0),
        "disconnected":    conn.get("disconnected", 0),
        "never_connected": conn.get("never_connected", 0),
        "pending":         conn.get("pending", 0),
    }


# ── SCA 合規 ─────────────────────────────────────────────

def get_sca(token: str, agent_id: str) -> list:
    """取得 agent 的 SCA 掃描結果（各 policy 摘要）。"""
    data = _get(token, f"/sca/{agent_id}")
    return data["data"]["affected_items"]


def get_sca_checks(token: str, agent_id: str, policy_id: str,
                   result: str = "failed", limit: int = 20) -> list:
    """取得某 SCA policy 下的 check 結果。result: passed/failed/not applicable"""
    data = _get(token, f"/sca/{agent_id}/checks/{policy_id}",
                {"result": result, "limit": limit})
    return data["data"]["affected_items"]


# ── Syscollector ──────────────────────────────────────────

def get_packages(token: str, agent_id: str, name_filter: str = None) -> list:
    """列出 agent 已安裝套件。"""
    params = {"limit": 100}
    if name_filter:
        params["name"] = name_filter
    data = _get(token, f"/syscollector/{agent_id}/packages", params)
    return data["data"]["affected_items"]


def get_ports(token: str, agent_id: str) -> list:
    """列出 agent 開放的 ports（listening）。"""
    data = _get(token, f"/syscollector/{agent_id}/ports",
                {"state": "listening", "limit": 200})
    return data["data"]["affected_items"]


def get_processes(token: str, agent_id: str, limit: int = 30) -> list:
    """列出 agent 執行中的 process。"""
    data = _get(token, f"/syscollector/{agent_id}/processes",
                {"limit": limit, "sort": "-resident"})
    return data["data"]["affected_items"]


def get_os_info(token: str, agent_id: str) -> dict:
    """取得 agent OS 資訊。"""
    data = _get(token, f"/syscollector/{agent_id}/os")
    items = data["data"]["affected_items"]
    return items[0] if items else {}


# ── Indexer 查詢（透過 Dashboard proxy）─────────────────────

_INDEXER_URL = f"https://{WAZUH_HOST}/api/console/proxy?path=wazuh-alerts-*%2F_search&method=GET"

def _indexer_search(query: dict) -> dict:
    """透過 Wazuh Dashboard proxy 查詢 OpenSearch alerts index。"""
    creds = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    payload = json.dumps(query).encode()
    req = urllib.request.Request(
        _INDEXER_URL,
        data=payload,
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json",
            "osd-xsrf":      "true",
        },
        method="POST",
    )
    res = urllib.request.urlopen(req, context=_CTX, timeout=15)
    return json.loads(res.read())


def get_dc_lockouts(agent_id: str = "002", hours: int = 24 * 7) -> list:
    """
    取得 DC 帳號鎖定事件（Event ID 4740）。
    回傳 [{ts, target_user, caller}]，依時間倒序。
    """
    data = _indexer_search({
        "query": {"bool": {"filter": [
            {"term":  {"agent.id": agent_id}},
            {"term":  {"data.win.system.eventID": "4740"}},
            {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        ]}},
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "data.win.eventdata"],
    })
    results = []
    for h in data["hits"]["hits"]:
        evt = h["_source"].get("data", {}).get("win", {}).get("eventdata", {})
        results.append({
            "ts":          h["_source"]["timestamp"][:19].replace("T", " "),
            "target_user": evt.get("targetUserName", ""),
            "caller":      evt.get("callerComputerName", ""),
        })
    return results


def get_dc_logon_failures(agent_id: str = "002", hours: int = 24,
                          username: str = None, limit: int = 50) -> list:
    """
    取得 DC 登入失敗事件（Event ID 4625）。
    回傳 [{ts, user, ip, workstation, logon_type, sub_status, process}]。
    sub_status 常見值：
      0xc000006a = 密碼錯誤
      0xc0000064 = 帳號不存在
      0xc0000234 = 帳號已鎖定
    """
    filters = [
        {"term":  {"agent.id": agent_id}},
        {"term":  {"data.win.system.eventID": "4625"}},
        {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
    ]
    if username:
        filters.append({"term": {"data.win.eventdata.targetUserName": username}})

    data = _indexer_search({
        "query": {"bool": {"filter": filters}},
        "size":  limit,
        "sort":  [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "data.win.eventdata"],
    })
    results = []
    for h in data["hits"]["hits"]:
        evt = h["_source"].get("data", {}).get("win", {}).get("eventdata", {})
        results.append({
            "ts":          h["_source"]["timestamp"][:19].replace("T", " "),
            "user":        evt.get("targetUserName", ""),
            "ip":          evt.get("ipAddress", ""),
            "workstation": evt.get("workstationName", ""),
            "logon_type":  evt.get("logonType", ""),
            "sub_status":  evt.get("subStatus", ""),
            "process":     (evt.get("processName") or "").rsplit("\\", 1)[-1],
        })
    return results


def get_dc_logon_failure_summary(agent_id: str = "002", hours: int = 24) -> dict:
    """
    彙整登入失敗統計，回傳 {total, by_user: [(user, count)], by_status: {status: count}}。
    """
    from collections import Counter
    data = _indexer_search({
        "query": {"bool": {"filter": [
            {"term":  {"agent.id": agent_id}},
            {"term":  {"data.win.system.eventID": "4625"}},
            {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        ]}},
        "size": 1000,
        "_source": ["data.win.eventdata.targetUserName", "data.win.eventdata.subStatus"],
    })
    by_user   = Counter()
    by_status = Counter()
    for h in data["hits"]["hits"]:
        evt = h["_source"].get("data", {}).get("win", {}).get("eventdata", {})
        by_user[evt.get("targetUserName", "")] += 1
        by_status[evt.get("subStatus", "")] += 1
    return {
        "total":     data["hits"]["total"]["value"],
        "by_user":   by_user.most_common(10),
        "by_status": dict(by_status),
    }


_SUB_STATUS = {
    "0xc000006a": "密碼錯誤",
    "0xc0000064": "帳號不存在",
    "0xc0000234": "帳號已鎖定",
    "0xc0000072": "帳號已停用",
    "0xc0000071": "密碼已到期",
    "0xc000015b": "未授權登入類型",
    "0xc0000193": "帳號已到期",
    "0xc0000070": "工作站限制",
    "0xc0000413": "驗證防火牆阻擋",
}


# ── 服務健康狀態 ──────────────────────────────────────────

# rule ID → (中文問題描述, 建議動作)
_RULE_MAP: dict[str, tuple[str, str]] = {
    "60602":  ("應用程式錯誤",      "查 Event Viewer → Application Log"),
    "61017":  ("服務異常終止",      "確認服務狀態，考慮重啟"),
    "61061":  ("多次應用程式錯誤",  "查 Event Viewer → Application Log"),
    "61107":  ("SSRS 服務停止",     "重啟 SSRS 並查原因"),
    "61110":  ("多次系統錯誤",      "查 Event Viewer → System Log，注意磁碟/驅動"),
    "60204":  ("多次登入失敗",      "確認帳號或來源 IP，評估是否封鎖"),
    "100002": ("帳號鎖定",          "解鎖前先查明來源，避免再次觸發"),
    "60109":  ("帳號啟用/新增",      "確認是否授權的帳號操作"),
    "60110":  ("帳號異動",          "確認是否授權的帳號變更"),
    "60111":  ("帳號停用/刪除",      "確認是否授權的帳號操作"),
    "60227":  ("外部裝置接入",        "確認設備是否授權（DC 上的 USB 需特別注意）"),
    # FIM — 登錄檔完整性
    "594":    ("FIM：登錄檔金鑰雜湊變更",  "確認是否為正常安裝/更新；非預期時需調查"),
    "750":    ("FIM：登錄檔值雜湊變更",    "確認是否為正常安裝/更新；非預期時需調查"),
    "751":    ("FIM：登錄檔值被刪除",      "確認是否授權操作；可能為軟體解安裝"),
    "752":    ("FIM：登錄檔值新增",        "確認是否授權操作；可能為軟體安裝或惡意持久化"),
    # VSS / 備份
    "60702":  ("VSS 服務關閉",            "確認備份任務是否正常完成；若非備份時段需調查"),
    # 授權
    "60646":  ("Windows 授權啟用失敗",    "執行 slmgr /ato 手動啟用；確認 KMS 伺服器可達"),
    # 服務設定
    "61102":  ("Windows 系統錯誤（單筆）", "查 Event Viewer → System 確認來源"),
    "61104":  ("服務啟動類型被變更",       "確認是否為授權的 IT 設定異動"),
    "92657":  ("NTLM 遠端登入",     "確認是否正常業務行為"),
    "23505":  ("CVE 漏洞偵測",      "執行 apt upgrade / yum update 修補"),
    "19003":  ("CIS SCA 分數低於 80%",       "登入主機，依 Wazuh SCA 失敗項逐一補強設定"),
    "19011":  ("CIS 合規缺失",               "參考 CIS Benchmark 修正設定"),
    "19013":  ("CIS 安全更新未套用（預警）",  "執行 dnf check-update 確認；排程執行 dnf update"),
    "19014":  ("CIS 安全更新未套用",          "立即執行 sudo dnf update -y 套用安全修補"),
    "81614":  ("VPN 登入失敗",      "確認來源 IP，評估是否需要封鎖"),
    "111016": ("ESXi root 登入",    "確認登入來源 IP 是否合法"),
}
# 這些 rule 是正常背景噪音，直接過濾
_NOISE_RULES = {"60112", "60106", "60642", "594", "750", "751", "752"}


def get_agent_issues(agent_names: list, hours: int = 24,
                     min_level: int = 8) -> dict:
    """
    批次查詢多個 agent 的 Wazuh 告警，回傳 {agent_name: [issues]}。
    每個 issue: {rule_id, zh, action, count, level, latest, sample}
    只回傳有問題的 agent（無問題不出現在 dict 中）。
    """
    if not agent_names:
        return {}

    noise_filter = [{"term": {"rule.id": r}} for r in _NOISE_RULES]
    q = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp":  {"gte": f"now-{hours}h"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"terms": {"agent.name": list(agent_names)}},
                ],
                "must_not": noise_filter,
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 200},
                "aggs": {
                    "by_rule": {
                        "terms": {"field": "rule.id", "size": 20},
                        "aggs": {
                            "max_level":  {"max":      {"field": "rule.level"}},
                            "latest":     {"max":      {"field": "timestamp"}},
                            "top_sample": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "_source": ["rule.description"],
                                }
                            },
                        },
                    }
                },
            }
        },
    }

    raw = _indexer_search(q)
    result: dict = {}

    for ab in raw.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
        aname  = ab["key"]
        issues = []
        for rb in ab.get("by_rule", {}).get("buckets", []):
            rid    = str(rb["key"])
            count  = rb["doc_count"]
            level  = int(rb["max_level"]["value"] or 0)
            latest = (rb["latest"]["value_as_string"] or "")[:19].replace("T", " ")
            top    = rb["top_sample"]["hits"]["hits"]
            sample = top[0]["_source"].get("rule", {}).get("description", "") if top else ""
            zh, action = _RULE_MAP.get(rid, (sample[:40] or f"rule {rid}", "確認告警詳情"))
            issues.append({
                "rule_id": rid,
                "zh":      zh,
                "action":  action,
                "count":   count,
                "level":   level,
                "latest":  latest,
                "sample":  sample,
            })
        issues.sort(key=lambda x: -x["level"])
        result[aname] = issues

    return result


# rule ID → (摘要說明, [(步驟標題, 步驟內容), ...])
_RULE_DETAIL: dict[str, tuple[str, list]] = {
    "61110": (
        "Windows System Log 在短時間內出現大量系統錯誤，常見原因：磁碟 I/O 問題、驅動程式崩潰或重要服務循環失敗。",
        [
            ("Event Viewer", "Windows Logs → System，篩選 Error / Critical，注意 Source 欄位"),
            ("磁碟健康",     "PowerShell：Get-PhysicalDisk | Select DeviceID, HealthStatus, OperationalStatus"),
            ("SMART 狀態",   "CrystalDiskInfo 或 diskpart 確認 Reallocated Sectors 等指標"),
            ("錯誤來源統計", "Get-EventLog -Log System -EntryType Error -Newest 50 | Group-Object Source | Sort Count -Desc"),
        ]
    ),
    "60602": (
        "Application Log 出現應用程式例外，通常是服務或第三方應用崩潰產生。",
        [
            ("Event Viewer", "Windows Logs → Application，篩選 Error，注意 Source 與 Event ID"),
            ("識別崩潰程式", "關注 .NET Runtime、Windows Error Reporting 的來源"),
            ("服務狀態",     "Get-Service | Where-Object {$_.Status -ne 'Running'}"),
        ]
    ),
    "61061": (
        "Application Log 在短時間內出現多筆同類應用程式錯誤，可能是某服務循環崩潰。",
        [
            ("找循環崩潰服務", "Event Viewer → Application，依時間排序，找重複 Source"),
            ("服務狀態",       "Get-Service | Where-Object {$_.Status -ne 'Running'}"),
            ("重啟並觀察",     "重啟後若持續出現，考慮修復或更新該應用"),
        ]
    ),
    "61017": (
        "重要服務意外停止，可能是程式崩潰、資源不足或手動停止觸發。",
        [
            ("識別服務",   "Event ID 7034/7036 可找到停止的服務名稱"),
            ("重啟服務",   "services.msc 或 Restart-Service <名稱>"),
            ("查崩潰原因", "Event Viewer → Application，找對應服務的 Error"),
        ]
    ),
    "61107": (
        "SSRS（SQL Server Reporting Services）服務停止，報表功能將無法使用。",
        [
            ("重啟服務",   "services.msc 找 SQL Server Reporting Services → 重新啟動"),
            ("查失敗原因", "Event Viewer → Application，Source = ReportingServicesService"),
            ("確認 SQL",   "確認後端 SQL Server 服務正常運作"),
        ]
    ),
    "60204": (
        "同一帳號短時間內多次登入失敗，可能是密碼錯誤、自動化程式憑證過期或暴力破解。",
        [
            ("確認失敗來源", "Event ID 4625，查 IpAddress 與 WorkstationName 欄位"),
            ("確認帳號狀態", "Search-ADAccount -LockedOut | Select Name, LockedOut"),
            ("評估封鎖",     "若來自外部或陌生 IP，考慮在防火牆封鎖"),
        ]
    ),
    "100002": (
        "帳號被鎖定，通常由多次密碼失敗自動觸發。未查明原因前不建議直接解鎖。",
        [
            ("查來源電腦",    "Event ID 4740，callerComputerName 欄位顯示觸發鎖定的來源"),
            ("確認是否暴力",  "查 Event ID 4625 同帳號的失敗紀錄"),
            ("解鎖帳號",      "Unlock-ADAccount -Identity <username>（確認安全後執行）"),
        ]
    ),
    "60110": (
        "偵測到帳號屬性異動（群組、描述、名稱等），確認是否為授權的 AD 維護操作。",
        [
            ("查 Event ID", "Event ID 4738（帳號異動）/ 4728/4732（加入群組）"),
            ("確認操作者",   "subjectUserName 欄位顯示執行異動的帳號"),
            ("與 IT 核對",   "若非排定維護，通知管理員確認"),
        ]
    ),
    "60109": (
        "偵測到帳號啟用或新建，確認是否為授權的人資/IT 操作。",
        [
            ("查 Event ID",  "Event ID 4720（帳號建立）/ 4722（帳號啟用）"),
            ("確認操作者",    "subjectUserName 欄位顯示執行操作的帳號"),
        ]
    ),
    "60111": (
        "偵測到帳號停用或刪除，確認是否為授權的離職/維護操作。",
        [
            ("查 Event ID",  "Event ID 4725（帳號停用）/ 4726（帳號刪除）"),
            ("確認操作者",    "subjectUserName 欄位顯示執行操作的帳號"),
        ]
    ),
    "23505": (
        "Wazuh 偵測到已知 CVE 漏洞，需盡快套用對應安全更新。",
        [
            ("確認套件版本", "dpkg -l <package> 或 rpm -q <package>"),
            ("套用更新",     "apt upgrade / yum update，重啟受影響服務"),
            ("驗證修補",     "更新後重新執行掃描確認漏洞已消除"),
        ]
    ),
    "60702": (
        "VSS（Volume Shadow Copy Service）服務關閉。正常備份任務完成後會關閉，但若在非備份時段頻繁出現，可能代表備份失敗或異常中止。",
        [
            ("確認備份排程", "查 Windows 工作排程器 / 備份軟體確認最近執行時間"),
            ("查事件記錄",   "Event Viewer → System，Source = VSS，看是否有 Error"),
            ("手動觸發備份", "若備份未完成，手動執行並觀察 VSS 是否正常啟停"),
        ]
    ),
    "60646": (
        "Windows 授權啟用（slui.exe）失敗。可能是 KMS 伺服器無法連線，或授權金鑰已過期。",
        [
            ("查授權狀態",    "PowerShell：Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.PartialProductKey} | Select Name, LicenseStatus"),
            ("手動啟用",      "cmd（管理員）：slmgr /ato"),
            ("確認 KMS",      "slmgr /skms <KMS_IP>:1688 → 再執行 slmgr /ato"),
        ]
    ),
    "61104": (
        "服務啟動類型被變更（自動→手動或停用）。可能是軟體安裝、系統更新或未授權的人為異動。",
        [
            ("查 Event ID 7040", "Event Viewer → System，Source = Service Control Manager，找服務名稱"),
            ("確認操作者",        "若有 Security Log，查 Event ID 4657 對應的帳號"),
            ("還原設定",          "services.msc 確認服務啟動類型是否符合預期"),
        ]
    ),
    "19011": (
        "CIS Benchmark 合規掃描發現設定不符，需依建議修正系統強化設定。",
        [
            ("查看詳細失敗項", "Wazuh → SCA → 此 agent 的掃描結果"),
            ("參考 CIS 文件",  "依對應 OS 版本的 CIS Benchmark 修正"),
            ("重新掃描",       "修正後執行 agent SCA 重新掃描驗證"),
        ]
    ),
    "19013": (
        "CIS Benchmark SCA 掃描偵測到系統安全更新尚未完整套用（預警級別）。",
        [
            ("確認 pending 套件", "ssh 登入後執行 dnf check-update 查看待更新清單"),
            ("排程更新",          "評估後排定維護時窗執行 sudo dnf update -y"),
            ("驗證",              "更新完成後重新觸發 SCA 掃描確認告警消除"),
        ]
    ),
    "19014": (
        "CIS Benchmark SCA 掃描確認系統安全更新未套用，存在已知漏洞暴露風險。",
        [
            ("立即更新",     "ssh 登入後執行 sudo dnf update -y 套用所有安全修補"),
            ("確認重啟需求", "執行 needs-restarting -r 確認是否需要重啟服務或主機"),
            ("驗證結果",     "更新後重新觸發 SCA 掃描，確認 19014 告警消除"),
        ]
    ),
    "19003": (
        "CIS Benchmark SCA 整體合規分數低於 80%，系統存在多項安全設定缺漏。",
        [
            ("查看失敗項清單", "Wazuh Dashboard → SCA → 此 agent → 展開失敗的 check 項目"),
            ("優先修正高風險項", "依 CIS Level 1 必要項目優先處理（SSH 設定、密碼原則、審計等）"),
            ("套用更新",        "先執行 sudo dnf update -y 排除因缺少更新造成的失敗項"),
            ("重新掃描驗證",    "每次修正後重跑 SCA，目標分數拉到 80% 以上"),
        ]
    ),
}


# Windows Event ID → (說明, 建議動作)
_WIN_EVENT_EXPLAIN: dict[str, tuple[str, str]] = {
    # Service Control Manager (Source: Service Control Manager)
    "7023": ("服務因錯誤而終止",
             "查 Event Viewer → System，注意服務名稱與錯誤碼，執行 Restart-Service <名稱>"),
    "7031": ("服務意外終止，SCM 已依設定採取復原動作",
             "確認服務是否持續崩潰；若是，查 Application Log 找對應 Source 的錯誤"),
    "7034": ("服務意外終止（非預期終止）",
             "確認服務狀態：Get-Service <名稱>；若持續崩潰查 Application Log"),
    "7036": ("服務狀態變更通知（running/stopped）",
             "本身為正常通知，但若高頻出現代表該服務不穩定，需查崩潰原因"),
    "7038": ("服務帳號密碼與 AD 不符，SCM 無法以指定帳號啟動服務",
             "到 services.msc → 找 Application 欄的服務 → 「登入」頁籤 → 輸入最新密碼，重新啟動服務"),
    "7000": ("服務無法啟動（Service failed to start）",
             "查錯誤碼；常見：2=找不到執行檔、1053=服務未及時回應；確認執行檔路徑與帳號權限"),
    "7001": ("服務因相依服務未啟動而失敗",
             "查 Depends on 的服務是否正常；先啟動相依服務再啟動此服務"),
    "7009": ("服務啟動逾時（等待回應超過 30 秒）",
             "確認服務執行檔是否存在、是否有足夠資源；可在登錄檔調高逾時值"),
    "7040": ("服務啟動類型（自動/手動/停用）被變更",
             "確認是否為排定的 IT 作業；若非預期需調查是哪個帳號執行了變更"),
    "7045": ("新服務被安裝到系統",
             "確認服務路徑合法；陌生路徑或亂碼名稱需立即調查（可能為惡意軟體持久化）"),
    # Application errors
    "1000": ("應用程式崩潰（Application Error / Faulting Application）",
             "查 Faulting application name；嘗試重啟、更新或修復該程式"),
    "1001": ("Windows Error Reporting 崩潰後報告（對應 Event 1000）",
             "與 Event 1000 配對查看；Fault bucket 可用於搜尋已知 bug"),
    "1002": ("應用程式無回應（Application Hang）",
             "重啟該應用程式；若持續發生需確認記憶體與 CPU 是否資源不足"),
    "1026": (".NET Runtime 未處理例外，應用程式崩潰",
             "查 Exception type 與 Stack trace；通常需更新 .NET 或修復應用程式"),
    "1027": (".NET Runtime 無法啟動（版本不相符）",
             "確認已安裝正確的 .NET Runtime 版本"),
    # Security / Logon
    "4624": ("帳號成功登入",
             "確認 Logon Type 與來源 IP 是否合法（特別是 Type 3 網路登入）"),
    "4625": ("帳號登入失敗",
             "查 Sub Status 碼：0xc000006a=密碼錯、0xc0000234=已鎖定；找來源 IP"),
    "4648": ("使用明確憑證登入（RunAs / 網路存取）",
             "確認是否為正常業務行為；頻繁出現需確認是否有憑證濫用"),
    "4720": ("建立了新的使用者帳號",
             "確認 Subject User（操作者）是否為授權 IT 人員"),
    "4722": ("使用者帳號已啟用",
             "確認是否為授權的復職/IT 操作"),
    "4725": ("使用者帳號已停用",
             "確認是否為授權的離職流程"),
    "4726": ("使用者帳號已刪除（不可逆）",
             "確認操作者；若非預期立即通知 AD 管理員"),
    "4740": ("使用者帳號被鎖定",
             "查 callerComputerName 欄位找觸發鎖定的來源電腦；處理後再解鎖"),
    "4738": ("使用者帳號屬性被異動",
             "確認 subjectUserName（操作者）與異動的屬性是否合理"),
    # System / Hardware
    "41":   ("Kernel-Power：系統非正常關機（無乾淨關機流程）",
             "檢查是否停電、過熱或 BSOD；查 %SystemRoot%\\Minidump 確認藍屏原因"),
    "6008": ("EventLog：上次系統關機為非預期關機",
             "查關機前後的事件；排查停電/過熱/BSOD；若有 Minidump 分析藍屏"),
    "55":   ("NTFS 檔案系統結構損毀（Ntfs 事件）",
             "立即執行：chkdsk C: /f /r（需重開機）；執行前先備份"),
    "98":   ("Windows 偵測到磁碟區損毀",
             "執行 chkdsk 修復；確認磁碟 SMART 健康狀態"),
    "129":  ("儲存控制器重置（StorPort/iaStor）",
             "可能為磁碟、HBA 或連接線問題；立即確認 SMART 並考慮替換磁碟"),
    "153":  ("磁碟 I/O 操作逾時後重試成功",
             "短期可繼續使用，但持續出現代表磁碟即將損壞；建議備份並排查"),
    # IIS
    "2269": ("IIS 應用程式集區崩潰並被停用",
             "到 IIS Manager 重新啟動集區；查 Application Log 找對應 Source 的崩潰原因"),
    # SQL Server
    "3041": ("SQL Server 備份作業失敗",
             "確認備份路徑磁碟空間；查 SQL Agent Job History；手動重跑備份測試"),
    "17806": ("SQL Server SSPI 認證握手失敗",
              "確認 SQL Server 服務帳號已設定正確 SPN；執行 setspn -L <帳號> 驗證"),
    "18456": ("SQL Server 登入失敗",
              "查 State 碼：18=密碼錯、38=資料庫不存在；確認連線字串與帳號"),
}


def get_rule_analysis(agent_name: str, rule_id: str, hours: int = 24) -> dict:
    """
    以 aggregation 分析特定 agent + rule 的事件分佈，避免大量 raw events 傳輸。
    回傳：
      total        : 總筆數
      by_source    : [{source, count, latest}]  依 Windows providerName 分組
      by_event_id  : [{event_id, count, latest}] 依 Windows eventID 分組
      by_hour      : [{hour, count}]             每小時分佈
      recent       : 最近 30 筆事件 [{ts, description, fields, full_log}]
    """
    base = [
        {"term":  {"agent.name": agent_name}},
        {"term":  {"rule.id":    rule_id}},
        {"range": {"timestamp":  {"gte": f"now-{hours}h"}}},
    ]
    q = {
        "size": 30,
        "query": {"bool": {"filter": base}},
        "sort":  [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.description", "rule.level", "data", "full_log"],
        "aggs": {
            "by_source": {
                "terms": {
                    "field":   "data.win.system.providerName",
                    "size":    20,
                    "missing": "n/a",
                },
                "aggs": {"latest": {"max": {"field": "timestamp"}}},
            },
            "by_event_id": {
                "terms": {
                    "field":   "data.win.system.eventID",
                    "size":    20,
                    "missing": "n/a",
                },
                "aggs": {"latest": {"max": {"field": "timestamp"}}},
            },
            "by_hour": {
                "date_histogram": {
                    "field":             "timestamp",
                    "fixed_interval":    "1h",
                    "min_doc_count":     1,
                },
            },
        },
    }

    raw   = _indexer_search(q)
    total = raw["hits"]["total"]["value"]
    aggs  = raw.get("aggregations", {})

    def _latest(b: dict) -> str:
        return (b.get("latest", {}).get("value_as_string") or "")[:19].replace("T", " ")

    by_source = [
        {"source": b["key"], "count": b["doc_count"], "latest": _latest(b)}
        for b in aggs.get("by_source", {}).get("buckets", [])
    ]
    by_event_id = []
    for b in aggs.get("by_event_id", {}).get("buckets", []):
        eid = str(b["key"])
        explain, ev_action = _WIN_EVENT_EXPLAIN.get(eid, ("", ""))
        by_event_id.append({
            "event_id": eid,
            "count":    b["doc_count"],
            "latest":   _latest(b),
            "explain":  explain,
            "action":   ev_action,
        })
    by_hour = [
        {
            "hour":  (b.get("key_as_string") or "")[:13].replace("T", " "),
            "count": b["doc_count"],
        }
        for b in aggs.get("by_hour", {}).get("buckets", [])
    ]

    recent = []
    for h in raw["hits"]["hits"]:
        src    = h["_source"]
        fields = _extract_fields(src.get("data", {}))
        eid    = fields.get("Event ID", "")
        explain, ev_action = _WIN_EVENT_EXPLAIN.get(eid, ("", ""))
        recent.append({
            "ts":          src.get("timestamp", "")[:19].replace("T", " "),
            "description": src.get("rule", {}).get("description", ""),
            "fields":      fields,
            "full_log":    (src.get("full_log") or "")[:600],
            "ev_explain":  explain,
            "ev_action":   ev_action,
        })

    return {
        "total":       total,
        "by_source":   by_source,
        "by_event_id": by_event_id,
        "by_hour":     by_hour,
        "recent":      recent,
    }


def get_agent_overview(agent_name: str, hours: int = 24, min_level: int = 3) -> dict:
    """
    取得 agent 全部 rule 的摘要分組（不限特定 rule），供 agent 全覽頁使用。
    回傳：
      total      : 總事件數
      by_rule    : [{rule_id, level, zh, action, count, latest,
                     by_event_id: [{event_id, count, explain}],  # Windows only
                     by_source:   [{source, count}]}]            # Linux fallback
    """
    q = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term":  {"agent.name": agent_name}},
            {"range": {"rule.level": {"gte": min_level}}},
            {"range": {"timestamp":  {"gte": f"now-{hours}h"}}},
        ]}},
        "aggs": {
            "total_hits": {"value_count": {"field": "rule.id"}},
            "by_rule": {
                "terms": {"field": "rule.id", "size": 50},
                "aggs": {
                    "max_level": {"max":  {"field": "rule.level"}},
                    "latest":    {"max":  {"field": "timestamp"}},
                    "by_event_id": {
                        "terms": {"field": "data.win.system.eventID", "size": 20},
                        "aggs":  {"latest": {"max": {"field": "timestamp"}}},
                    },
                    "by_source": {
                        "terms": {"field": "data.srcuser", "size": 10,
                                  "missing": ""},
                    },
                },
            },
        },
    }
    raw   = _indexer_search(q)
    total = raw["hits"]["total"]["value"]
    aggs  = raw.get("aggregations", {})

    def _latest(b):
        return (b.get("latest", {}).get("value_as_string") or "")[:19].replace("T", " ")

    rules = []
    for rb in aggs.get("by_rule", {}).get("buckets", []):
        rid   = str(rb["key"])
        level = int(rb.get("max_level", {}).get("value") or 0)
        zh, action = _RULE_MAP.get(rid, ("", "確認告警詳情"))
        if not zh:
            zh = f"rule {rid}"

        by_eid = []
        for eb in rb.get("by_event_id", {}).get("buckets", []):
            eid = str(eb["key"])
            if eid == "n/a" or not eid:
                continue
            explain, _ = _WIN_EVENT_EXPLAIN.get(eid, ("", ""))
            by_eid.append({"event_id": eid, "count": eb["doc_count"], "explain": explain,
                           "latest": _latest(eb)})

        by_src = [
            {"source": b["key"], "count": b["doc_count"]}
            for b in rb.get("by_source", {}).get("buckets", [])
            if b["key"]
        ]

        rules.append({
            "rule_id":     rid,
            "level":       level,
            "zh":          zh,
            "action":      action,
            "count":       rb["doc_count"],
            "latest":      _latest(rb),
            "by_event_id": by_eid,
            "by_source":   by_src,
        })

    rules.sort(key=lambda r: (-r["level"], -r["count"]))
    return {"total": total, "by_rule": rules}


def get_eventid_events(agent_name: str, rule_id: str, event_id: str,
                       hours: int = 24, limit: int = 300) -> dict:
    """
    取得特定 agent + rule + Windows event_id 的所有事件。
    回傳 {total, events: [{ts, description, fields, full_log}]}
    """
    q = {
        "query": {"bool": {"filter": [
            {"term":  {"agent.name":              agent_name}},
            {"term":  {"rule.id":                 rule_id}},
            {"term":  {"data.win.system.eventID": event_id}},
            {"range": {"timestamp":               {"gte": f"now-{hours}h"}}},
        ]}},
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.description", "rule.level", "data", "full_log"],
    }
    raw    = _indexer_search(q)
    total  = raw["hits"]["total"]["value"]
    events = []
    for h in raw["hits"]["hits"]:
        src    = h["_source"]
        fields = _extract_fields(src.get("data", {}))
        events.append({
            "ts":          src.get("timestamp", "")[:19].replace("T", " "),
            "description": src.get("rule", {}).get("description", ""),
            "fields":      fields,
            "full_log":    (src.get("full_log") or "")[:800],
        })
    return {"total": total, "events": events}


def get_rule_events(agent_name: str, rule_id: str,
                    hours: int = 24, limit: int = 50) -> list:
    """
    取得特定 agent + rule 的實際事件清單。
    回傳 [{ts, description, level, fields, full_log}]
    fields 為從 data 萃取的關鍵欄位 dict（Event ID、帳號、IP 等）。
    """
    q = {
        "query": {"bool": {"filter": [
            {"term":  {"agent.name": agent_name}},
            {"term":  {"rule.id":    rule_id}},
            {"range": {"timestamp":  {"gte": f"now-{hours}h"}}},
        ]}},
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.description", "rule.level", "full_log", "data"],
    }
    raw = _indexer_search(q)
    results = []
    for h in raw["hits"]["hits"]:
        src  = h["_source"]
        data = src.get("data", {})
        results.append({
            "ts":          src.get("timestamp", "")[:19].replace("T", " "),
            "description": src.get("rule", {}).get("description", ""),
            "level":       src.get("rule", {}).get("level", 0),
            "fields":      _extract_fields(data),
            "full_log":    (src.get("full_log") or "")[:800],
        })
    return results


def _extract_fields(data: dict) -> dict:
    """從事件 data 欄位萃取常見的關鍵資訊。"""
    out = {}
    win = data.get("win", {})
    if win:
        sys_  = win.get("system", {})
        evt   = win.get("eventdata", {})
        if sys_.get("eventID"):
            out["Event ID"] = sys_["eventID"]
        if sys_.get("channel"):
            out["Channel"] = sys_["channel"]
        if sys_.get("providerName"):
            out["Source"] = sys_["providerName"]
        for key, label in [
            ("targetUserName",    "Target User"),
            ("subjectUserName",   "Subject User"),
            ("ipAddress",         "Source IP"),
            ("callerComputerName","Caller"),
            ("workstationName",   "Workstation"),
            ("param1",            "Application"),
            ("param2",            "Error"),
            ("memberName",        "Member"),
            ("logonType",         "Logon Type"),
            ("subStatus",         "Sub Status"),
        ]:
            v = evt.get(key, "")
            if v and v not in ("-", "0x0", "%%1796", "S-1-0-0"):
                out[label] = v
    # Linux / generic
    for key, label in [
        ("srcip",    "Source IP"),
        ("dstip",    "Dest IP"),
        ("srcport",  "Src Port"),
        ("dstport",  "Dst Port"),
        ("srcuser",  "User"),
    ]:
        if data.get(key):
            out.setdefault(label, data[key])
    return out


def get_service_health(hours: int = 24, min_level: int = 8) -> list[dict]:
    """
    依 inventory.yaml services 定義，彙整各服務的 Wazuh 告警。
    回傳 list of {service, desc, issues}
    每個 issue: {label, agent, rule_id, zh, action, count, level, latest, sample}
    只回傳有問題的服務（issues 非空）。
    """
    import yaml
    from pathlib import Path

    inv_path = Path(__file__).parent.parent / "inventory.yaml"
    inv = yaml.safe_load(inv_path.read_text())

    # 建立 wazuh_agent → {service_key, desc, label} 的對應表
    agent_map: dict[str, dict] = {}
    for h in inv.get("dashboard_servers", []):
        wname = h.get("wazuh")
        if wname:
            team = h.get("team", "Unknown")
            agent_map[wname] = {
                "service": team,
                "desc":    h.get("desc", wname),
                "label":   h.get("label", wname),
            }

    if not agent_map:
        return []

    # 一次查詢所有有 wazuh agent 的機器
    noise_filter = [{"term": {"rule.id": r}} for r in _NOISE_RULES]
    q = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp":  {"gte": f"now-{hours}h"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"terms": {"agent.name": list(agent_map.keys())}},
                ],
                "must_not": noise_filter,
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 200},
                "aggs": {
                    "by_rule": {
                        "terms": {"field": "rule.id", "size": 20},
                        "aggs": {
                            "max_level":  {"max":      {"field": "rule.level"}},
                            "latest":     {"max":      {"field": "timestamp"}},
                            "top_sample": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "_source": ["rule.description", "rule.level"],
                                }
                            },
                        },
                    }
                },
            }
        },
    }

    raw = _indexer_search(q)

    # 整理成 service → issues 結構
    svc_issues: dict[str, list] = {}
    for agent_bucket in raw.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
        aname = agent_bucket["key"]
        meta  = agent_map.get(aname, {})
        skey  = meta.get("service", "Unknown")
        label = meta.get("label", aname)

        for rule_bucket in agent_bucket.get("by_rule", {}).get("buckets", []):
            rid   = str(rule_bucket["key"])
            count = rule_bucket["doc_count"]
            level = int(rule_bucket["max_level"]["value"] or 0)
            latest_ts = (rule_bucket["latest"]["value_as_string"] or "")[:19].replace("T", " ")
            top = rule_bucket["top_sample"]["hits"]["hits"]
            sample = top[0]["_source"].get("rule", {}).get("description", "") if top else ""

            zh, action = _RULE_MAP.get(rid, (sample[:40] or f"rule {rid}", "確認告警詳情"))

            svc_issues.setdefault(skey, []).append({
                "label":   label,
                "agent":   aname,
                "rule_id": rid,
                "zh":      zh,
                "action":  action,
                "count":   count,
                "level":   level,
                "latest":  latest_ts,
                "sample":  sample,
            })

    # 組成最終結果，level 高的排前面
    result = []
    for svc_key in sorted(svc_issues.keys()):
        issues = svc_issues.get(svc_key, [])
        if not issues:
            continue
        issues.sort(key=lambda x: (-x["level"], x["label"]))
        result.append({
            "service": svc_key,
            "desc":    svc_key,
            "issues":  issues,
        })

    return result


def format_service_health(data: list[dict]) -> str:
    """將 get_service_health() 結果格式化為可讀報告。"""
    if not data:
        return "  ✅ 所有服務無異常"

    lines = []
    for svc in data:
        lines.append(f"\n  【{svc['service']} {svc['desc']}】")
        # 同一台機器同規則只顯示一次，依 label 分組
        seen = {}
        for issue in svc["issues"]:
            key = (issue["label"], issue["rule_id"])
            if key not in seen:
                seen[key] = issue
        for issue in seen.values():
            icon = "🔴" if issue["level"] >= 10 else "🟠"
            lines.append(
                f"    {icon} {issue['label']:<22} {issue['zh']}"
                f"  ×{issue['count']}  最近：{issue['latest']}"
            )
            lines.append(f"       → {issue['action']}")
    return "\n".join(lines)


# ── 報告 ──────────────────────────────────────────────────

def agent_status_report(token: str) -> str:
    """所有 agent 狀態報告。"""
    summary = get_agent_summary(token)
    agents  = get_agents(token)

    disconnected = [a for a in agents if a.get("status") == "disconnected"]
    never        = [a for a in agents if a.get("status") == "never_connected"]

    lines = ["=" * 55, "  Wazuh Agent 狀態報告", "=" * 55]
    lines.append(f"\n共 {summary.get('total', 0)} 個 agent")
    lines.append(f"  ✅ active        : {summary.get('active', 0)}")
    lines.append(f"  ❌ disconnected  : {summary.get('disconnected', 0)}")
    lines.append(f"  ⬜ never_connected: {summary.get('never_connected', 0)}")
    lines.append(f"  🔄 pending       : {summary.get('pending', 0)}")

    if disconnected:
        lines.append(f"\n【離線 Agent】")
        for a in disconnected:
            last = a.get("lastKeepAlive", "unknown")[:10]
            lines.append(f"  ❌ {a.get('name',''):<30} {a.get('ip',''):<16} 最後上線：{last}")

    if never:
        lines.append(f"\n【從未連線】")
        for a in never:
            lines.append(f"  ⬜ {a.get('name',''):<30} {a.get('ip',''):<16}")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


def sca_report(token: str, agent_name: str) -> str:
    """指定 agent 的 SCA 合規報告。"""
    agent = get_agent_by_name(token, agent_name)
    if not agent:
        return f"找不到 agent: {agent_name}"

    agent_id = agent["id"]
    os_name  = agent.get("os", {}).get("name", "unknown OS")
    policies = get_sca(token, agent_id)

    lines = [f"=== SCA 合規報告：{agent_name} ({os_name}) ==="]
    for p in policies:
        score = p.get("score", 0)
        icon  = "✅" if score >= 80 else ("🟡" if score >= 60 else "🔴")
        lines.append(f"\n{icon} [{p.get('name','')}]")
        lines.append(f"   通過：{p.get('pass',0)}  失敗：{p.get('fail',0)}  "
                     f"N/A：{p.get('invalid',0)}  分數：{score}%")
        lines.append(f"   最後掃描：{str(p.get('end_scan',''))[:16]}")

        # 列前幾個失敗項
        failed = get_sca_checks(token, agent_id, p["policy_id"], result="failed", limit=5)
        if failed:
            lines.append("   失敗項（前 5）：")
            for c in failed:
                lines.append(f"     • {c.get('title','')[:80]}")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    t = login()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        print(agent_status_report(t))
    elif cmd == "sca" and len(sys.argv) > 2:
        print(sca_report(t, sys.argv[2]))
    elif cmd == "ports" and len(sys.argv) > 2:
        agent = get_agent_by_name(t, sys.argv[2])
        if agent:
            ports = get_ports(t, agent["id"])
            print(f"=== {sys.argv[2]} 開放 ports ===")
            for p in ports:
                print(f"  {p.get('protocol',''):<5} {p.get('local_ip',''):<18}:{p.get('local_port','')} "
                      f"  {p.get('process','')}")
        else:
            print("找不到 agent")
    elif cmd == "agents":
        agents = get_agents(t)
        for a in agents:
            icon = AGENT_STATUS_EMOJI.get(a.get("status",""), "?")
            print(f"{icon} {a.get('name',''):<30} {a.get('ip',''):<16} "
                  f"{a.get('os',{}).get('name','')[:30]}")
    elif cmd == "lockouts":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 168
        rows  = get_dc_lockouts(hours=hours)
        print(f"帳號鎖定事件（近 {hours}h）：{len(rows)} 筆")
        for r in rows:
            print(f"  [{r['ts']}] {r['target_user']:<20} caller={r['caller'] or '—'}")
    elif cmd == "failures":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        user  = sys.argv[3] if len(sys.argv) > 3 else None
        if user:
            rows = get_dc_logon_failures(hours=hours, username=user)
            print(f"{user} 登入失敗（近 {hours}h）：{len(rows)} 筆")
            for r in rows:
                status_label = _SUB_STATUS.get(r['sub_status'], r['sub_status'])
                print(f"  [{r['ts']}] {status_label}  process={r['process']}")
        else:
            s = get_dc_logon_failure_summary(hours=hours)
            print(f"登入失敗摘要（近 {hours}h）：共 {s['total']} 筆")
            print("Top 帳號：")
            for user, cnt in s["by_user"]:
                print(f"  {user:<25} {cnt} 次")
            print("失敗原因：")
            for status, cnt in sorted(s["by_status"].items(), key=lambda x: -x[1]):
                label = _SUB_STATUS.get(status, status)
                print(f"  {label:<20} {cnt} 次")
