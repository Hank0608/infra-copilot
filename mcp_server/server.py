"""infra-copilot MCP Server — 把既有 tools/*.py 的唯讀查詢函式包成 MCP tool。

只暴露 get_* 這類唯讀函式，不暴露 ssh(host, cmd) 這種任意命令執行的底層 primitive。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from mcp.server.fastmcp import FastMCP

from tools import (
    ad_runner,
    dell_me_runner,
    fortigate_runner,
    linux_runner,
    ppdm_runner,
    synology_runner,
    vsphere_runner,
    wazuh_runner,
    zabbix_runner,
)
from mcp_server.session_cache import call_with_retry

mcp = FastMCP("infra-copilot")


# ── Zabbix ────────────────────────────────────────────────

@mcp.tool()
def zabbix_problems(min_severity: int = 2, days: int = 30) -> list:
    """查詢 Zabbix 目前未解決的問題（problem）。當有人問「現在有哪些告警/問題」、
    「有沒有高優先度的事件還沒處理」時呼叫。
    min_severity: 2=Warning, 3=Average, 4=High, 5=Disaster，數字越大越嚴重。"""
    return call_with_retry("zabbix", zabbix_runner.login, zabbix_runner.get_problems,
                            min_severity=min_severity, days=days)


@mcp.tool()
def zabbix_host_availability() -> dict:
    """查詢所有 Zabbix 監控主機目前是 up/down/unknown。當有人問「現在有哪些主機斷線」
    時呼叫。"""
    return call_with_retry("zabbix", zabbix_runner.login, zabbix_runner.get_host_availability)


@mcp.tool()
def zabbix_disk_growth(hostname: str, days: int = 90) -> dict:
    """分析指定主機在 N 天內的磁碟成長趨勢，估算還有多久會滿。當有人問「這台主機的
    磁碟還能撐多久」、「磁碟成長速度」時呼叫。hostname 是 Zabbix 上的主機名稱。"""
    return zabbix_runner.get_disk_growth(hostname, days=days)


# ── Wazuh ─────────────────────────────────────────────────

@mcp.tool()
def wazuh_agent_summary() -> dict:
    """查詢 Wazuh agent 連線狀態統計（active/disconnected/never_connected/pending
    各幾台）。當有人問「有多少台 agent 斷線」時呼叫。"""
    return call_with_retry("wazuh", wazuh_runner.login, wazuh_runner.get_agent_summary)


@mcp.tool()
def wazuh_agent_issues(agent_names: list[str], hours: int = 24, min_level: int = 8) -> dict:
    """批次查詢多個主機在 Wazuh 上的安全告警（已過濾掉背景噪音）。當有人問「這幾台
    主機最近有沒有安全事件」時呼叫，agent_names 是 Wazuh 上的 agent 名稱列表。"""
    return wazuh_runner.get_agent_issues(agent_names, hours=hours, min_level=min_level)


@mcp.tool()
def wazuh_service_health(hours: int = 24, min_level: int = 8) -> list:
    """依 inventory.yaml 定義的服務清單，彙整每個服務對應主機的 Wazuh 告警。當有人問
    「現在哪些服務有安全問題」時呼叫，不需要指定主機名稱。"""
    return wazuh_runner.get_service_health(hours=hours, min_level=min_level)


# ── vSphere ───────────────────────────────────────────────

@mcp.tool()
def vsphere_all_vms() -> list:
    """列出 vCenter 上所有 VM 及其電源狀態。當有人問「現在有哪些 VM」時呼叫。"""
    return vsphere_runner.get_all_vms()


@mcp.tool()
def vsphere_datastores() -> list:
    """列出所有 datastore 用量，依使用率高到低排序。當有人問「哪個 datastore 快滿了」
    時呼叫。"""
    return vsphere_runner.get_datastores()


@mcp.tool()
def vsphere_active_alarms() -> list:
    """列出 vCenter 目前觸發中的告警。當有人問「vCenter 現在有沒有告警」時呼叫。"""
    return vsphere_runner.get_active_alarms()


@mcp.tool()
def vsphere_recent_events(hours: int = 24) -> list:
    """列出 vCenter 最近 N 小時的事件記錄。當有人問「最近 vCenter 發生了什麼事」時
    呼叫。"""
    return vsphere_runner.get_recent_events(hours=hours)


# ── PPDM 備份 ─────────────────────────────────────────────

@mcp.tool()
def ppdm_backup_summary(hours: int = 24) -> dict:
    """查詢最近 N 小時的備份作業成功/失敗統計。當有人問「昨晚備份有沒有跑成功」時
    呼叫。"""
    return call_with_retry("ppdm", ppdm_runner.login, ppdm_runner.get_backup_summary,
                            hours=hours)


@mcp.tool()
def ppdm_failed_jobs(limit: int = 20) -> list:
    """查詢最近失敗的備份作業清單。當有人問「哪些備份失敗了」時呼叫。"""
    return call_with_retry("ppdm", ppdm_runner.login, ppdm_runner.get_failed_jobs,
                            limit=limit)


# ── Synology ──────────────────────────────────────────────

@mcp.tool()
def synology_nas_list() -> list:
    """列出所有 Synology NAS 主機清單。當有人問「有幾台 NAS」時呼叫。"""
    return synology_runner.get_nas_list()


@mcp.tool()
def synology_backup_status() -> list:
    """查詢 Synology Active Backup for Business 的備份狀態。當有人問「NAS 的備份
    狀況」時呼叫。"""
    return call_with_retry("synology", synology_runner.login,
                            synology_runner.get_backup_status)


# ── Linux ─────────────────────────────────────────────────

@mcp.tool()
def linux_system_info(host: str) -> dict:
    """查詢 Linux 主機的 OS、kernel、hostname、uptime。host 可為 IP 或 inventory.yaml
    裡的 label。當有人問「這台主機是什麼系統」時呼叫。"""
    return linux_runner.get_system_info(host)


@mcp.tool()
def linux_load(host: str) -> dict:
    """查詢 Linux 主機的 CPU 負載。當有人問「這台主機 CPU 負載高不高」時呼叫。"""
    return linux_runner.get_load(host)


@mcp.tool()
def linux_disk(host: str) -> list:
    """查詢 Linux 主機各掛載點的磁碟使用率。當有人問「這台主機磁碟夠不夠用」時
    呼叫。"""
    return linux_runner.get_disk(host)


@mcp.tool()
def linux_memory(host: str) -> dict:
    """查詢 Linux 主機的記憶體使用狀況。當有人問「這台主機記憶體夠不夠」時呼叫。"""
    return linux_runner.get_memory(host)


# ── AD ────────────────────────────────────────────────────

@mcp.tool()
def ad_locked_accounts() -> list:
    """查詢目前被鎖定的 AD 帳號。當有人問「有哪些帳號被鎖住」時呼叫。"""
    return ad_runner.get_locked_accounts()


@mcp.tool()
def ad_expiring_passwords(days: int = 14) -> list:
    """查詢 N 天內密碼即將到期的 AD 帳號。當有人問「有誰的密碼快過期」時呼叫。"""
    return ad_runner.get_expiring_passwords(days=days)


# ── Dell ME SAN ───────────────────────────────────────────

@mcp.tool()
def dell_me_disk_summary(host: str) -> dict:
    """查詢指定 Dell ME SAN 主機的磁碟組摘要。當有人問「SAN 還有多少空間」時呼叫，
    host 是 ME 設備的 IP。"""
    return dell_me_runner.get_disk_summary(host)


@mcp.tool()
def dell_me_all_system_info() -> list:
    """查詢所有 Dell ME SAN 設備的系統資訊。當有人問「有幾台 SAN、狀態如何」時
    呼叫。"""
    return dell_me_runner.get_all_system_info()


# ── FortiGate ─────────────────────────────────────────────

@mcp.tool()
def fortigate_system_status() -> dict:
    """查詢 FortiGate 防火牆的系統狀態。當有人問「防火牆狀態正常嗎」時呼叫。"""
    return call_with_retry("fortigate", fortigate_runner.login,
                            fortigate_runner.get_system_status)


@mcp.tool()
def fortigate_interfaces() -> list:
    """查詢 FortiGate 防火牆的網路介面清單與狀態。當有人問「防火牆有哪些介面」時
    呼叫。"""
    return call_with_retry("fortigate", fortigate_runner.login,
                            fortigate_runner.get_interfaces)


if __name__ == "__main__":
    import os

    # 本機開發用 stdio，部署到 VM 後改用 streamable-http（見 MCP_SERVER_PLAN.md Phase 3）
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = int(os.getenv("MCP_PORT", "8000"))
        # FastMCP 預設只允許 Host: localhost/127.0.0.1（DNS rebinding 防護），
        # 部署機要用 IP 連線，得把實際 host:port 加進白名單
        allowed_host = os.getenv("MCP_ALLOWED_HOST")
        if allowed_host:
            mcp.settings.transport_security.allowed_hosts.append(allowed_host)
            mcp.settings.transport_security.allowed_origins.append(f"http://{allowed_host}")
    mcp.run(transport=transport)
