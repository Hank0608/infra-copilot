"""統一憑證存取 — 密碼從 macOS Keychain 取得，其餘設定從 .env。"""

import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
load_dotenv(ROOT / ".env")

_SERVICE = "infra-copilot"
_PASS_KEYS = {"RP_PASS", "AD_PASS", "FW_PASS", "ZABBIX_PASS", "WAZUH_PASS", "PPDM_PASS", "SYNOLOGY_PASS", "LDAP_SVC_PASS", "TEAMS_WEBHOOK_URL", "SMTP_PASS", "MCP_VM_PASS"}

# 這些服務都用 infra.ro 帳號，密碼相同，set-all 時合併成一次輸入
_INFRA_RO_KEYS = ["AD_PASS", "LDAP_SVC_PASS", "ZABBIX_PASS", "WAZUH_PASS", "SYNOLOGY_PASS", "PPDM_PASS", "FW_PASS", "SMTP_PASS", "RP_PASS"]

# 顯示順序（方便 status / set-all 時對照用途）
_KEY_ORDER = [
    ("LDAP_SVC_PASS",    "LDAP service account (infra_ldap，與 infra.ro 同密碼) — vSphere / Dell ME / SSH"),
    ("AD_PASS",          "AD 管理帳號密碼（infra.ro）"),
    ("ZABBIX_PASS",      "Zabbix API token / 密碼"),
    ("WAZUH_PASS",       "Wazuh API 密碼"),
    ("PPDM_PASS",        "PPDM API 密碼"),
    ("SYNOLOGY_PASS",    "Synology DSM 密碼"),
    ("FW_PASS",          "FortiGate 密碼"),
    ("TEAMS_WEBHOOK_URL","Teams Webhook URL"),
    ("SMTP_PASS",        "SMTP 密碼（若有）"),
    ("RP_PASS",          "Reverse proxy（infra.ro）"),
    ("MCP_VM_PASS",      "MCP Server VM (10.200.80.39) SSH 密碼 — ubiqconn"),
]


def get(key: str, fallback: str = "") -> str:
    """取得設定值。密碼類從 Keychain 取，其餘從 .env。"""
    if key in _PASS_KEYS:
        try:
            import keyring
            val = keyring.get_password(_SERVICE, key)
            if val:
                return val
        except Exception:
            pass
    return os.getenv(key, fallback)


def set_secret(key: str, value: str) -> None:
    """把密碼存入 Keychain（透過 security 指令，不受 codesign 限制）。"""
    if key not in _PASS_KEYS:
        raise ValueError(f"未知的 key: {key}，允許: {sorted(_PASS_KEYS)}")
    import subprocess

    # 確保 login.keychain 是解鎖的
    subprocess.run(
        ["security", "unlock-keychain",
         os.path.expanduser("~/Library/Keychains/login.keychain-db")],
        capture_output=True,
    )

    r = subprocess.run(
        ["security", "add-generic-password", "-s", _SERVICE, "-a", key, "-w", value, "-U"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"security 寫入失敗 (exit {r.returncode}): {r.stderr.strip() or r.stdout.strip()}")


def status() -> dict[str, bool]:
    """回傳各 key 是否已設定。"""
    import keyring
    return {k: bool(keyring.get_password(_SERVICE, k)) for k in _PASS_KEYS}


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cmd_status():
    s = status()
    print(f"{'KEY':<20} {'狀態':<8} 說明")
    print("-" * 60)
    for key, desc in _KEY_ORDER:
        mark = "OK" if s.get(key) else "MISSING"
        print(f"{key:<20} {mark:<8} {desc}")


def _cmd_set(key: str):
    import getpass
    if key not in _PASS_KEYS:
        print(f"未知 key: {key}")
        return
    val = getpass.getpass(f"{key}: ")
    if not val.strip():
        print("未輸入，略過")
        return
    set_secret(key, val)
    print(f"{key} 已儲存")


def _cmd_set_all():
    import getpass
    s = status()

    shared = getpass.getpass(f"infra.ro 帳號密碼（套用到 {', '.join(_INFRA_RO_KEYS)}，Enter 跳過）: ")
    if shared.strip():
        for key in _INFRA_RO_KEYS:
            set_secret(key, shared)
            print(f"  {key} 已儲存")

    for key, desc in _KEY_ORDER:
        if key in _INFRA_RO_KEYS:
            continue
        current = "OK" if s.get(key) else "MISSING"
        val = getpass.getpass(f"[{current}] {key} ({desc}): ")
        if not val.strip():
            print(f"  略過")
            continue
        set_secret(key, val)
        print(f"  已儲存")


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if not args or args[0] == "status":
        _cmd_status()
    elif args[0] == "set" and len(args) == 2:
        _cmd_set(args[1])
    elif args[0] == "set-all":
        _cmd_set_all()
    else:
        print("用法:")
        print("  python3 -m tools.secrets status       # 檢查所有密碼狀態")
        print("  python3 -m tools.secrets set KEY      # 設定單一密碼")
        print("  python3 -m tools.secrets set-all      # 逐一設定所有密碼")
