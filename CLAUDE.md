# infra-copilot 行為規範

## 基本原則

- 有 runner 就用 runner，**不准自己寫 raw API call 或 ad-hoc 腳本**
- 所有查詢（read-only）直接執行，不需要請求許可
- 修改、新增、刪除任何設定前必須先告知使用者，確認後才動手
- 診斷問題時聚焦在問題本身，不擴散到無關的系統或設定

---

## 憑證與密碼

密碼統一透過 `tools.secrets` 模組存取，**不可使用 `security` 指令直接讀取 Keychain**：

```python
from tools.secrets import get as _secret
pw = _secret("WAZUH_PASS")
```

Keychain service 名稱為 `infra-copilot`，所有 key 名稱：

| Key | 用途 |
|---|---|
| `ZABBIX_PASS` | Zabbix API 密碼 |
| `WAZUH_PASS` | Wazuh API 密碼 |
| `PPDM_PASS` | PPDM API 密碼 |
| `SYNOLOGY_PASS` | Synology DSM 密碼 |
| `FW_PASS` | FortiGate 密碼 |
| `AD_PASS` | AD 管理帳號密碼 (hank_lin@uti.com) |
| `LDAP_SVC_PASS` | LDAP service account (infra_ldap) |
| `RP_PASS` | Reverse proxy |
| `SMTP_PASS` | SMTP 密碼 |
| `TEAMS_WEBHOOK_URL` | Teams Webhook URL |

若讀不到密碼，先問使用者是否更換過密碼、是否需要執行 `python3 -m tools.secrets set KEY` 重新設定，**不要嘗試其他 Keychain 路徑**。

環境變數（非敏感設定如 IP、帳號名稱）從 `.env` 讀取，`tools.secrets` 匯入時已自動 `load_dotenv`。

---

## Runner 對照表

| 系統 | Runner | 涵蓋操作 |
|---|---|---|
| Zabbix | `tools/zabbix_runner.py` | 問題查詢、磁碟報告、主機狀態、web scenario |
| Wazuh | `tools/wazuh_runner.py` | agent 狀態、SCA 合規、syscollector |
| vSphere / ESXi | `tools/vsphere_runner.py` | VM 清單、CPU/記憶體、datastore、效能時序 |
| Dell ME SAN | `tools/dell_me_runner.py` | 磁碟組、volume、效能 |
| Synology NAS | `tools/synology_runner.py` | 磁碟區、快照、空間使用 |
| PPDM 備份 | `tools/ppdm_runner.py` | 備份任務狀態、asset 清單 |
| FortiGate | `tools/fortigate_runner.py` | 介面、路由、policy |
| AD / LDAP | `tools/ad_runner.py` | 使用者查詢、群組、密碼原則 |
| Linux 主機 | `tools/linux_runner.py` | 磁碟、CPU、服務狀態（via SSH） |
| Linux 診斷 | `tools/linux_diag.py` | 問題診斷流程 |
| SSH | `tools/ssh_runner.py` | 通用 SSH 執行 |
| DNS | `tools/dns_runner.py` | DNS 解析查詢 |
| K8s | `tools/k8s_runner.py` | pod、service、namespace |
| MySQL | `tools/mysql_runner.py` | 資料庫查詢 |
| SMTP | `tools/smtp_runner.py` | 郵件測試 |

使用前先閱讀 runner 的 docstring 或列出可用函式，確認功能是否存在，**不要因為 runner 沒有某功能就改為自己寫**。若 runner 缺少必要功能，告知使用者並提議將新功能補進 runner。

---

## Zabbix API 注意事項

Zabbix 7.x 使用 **Bearer token** 認證，不是舊版的 `auth` 欄位：

```python
# 正確
headers = ['-H', f'Authorization: Bearer {token}']

# 錯誤（舊版寫法）
payload = {"auth": token, ...}
```

帳號為 `.env` 中的 `ZABBIX_USER`（目前 `infra.ro`）。

---

## 工作目錄

所有腳本從 `/Users/hank_lin/infra-copilot/` 執行：

```bash
cd /Users/hank_lin/infra-copilot && python3 -m tools.zabbix_runner ...
```

---

## 診斷優先順序

問題診斷時依以下順序，確認當前層沒問題再往下：

1. 本機（iostat、df、top）
2. 應用層（服務狀態、log）
3. 儲存層（SAN dg-stats、san-report）
4. 網路層（ping、traceroute、介面統計）

不在同一個問題裡同時診斷多個不相關的系統。

---

## 日報

執行日報預設加 `--file` 存到 `~/Documents/daily_report`：

```bash
python3 daily_report.py --file ~/Documents/daily_report/YYYY-MM-DD.md
```
