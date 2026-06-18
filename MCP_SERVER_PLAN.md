# infra-copilot MCP Server 落地計畫

> 狀態：已核准，尚未開始執行（Phase 1 待啟動）
> 建立日期：2026-06-17

## Context

Hank 正在準備轉職（方向：AI/LLM 應用 + Platform/DevOps/SRE 混合），需要在 1-2 個月內有一個可在面試展示的「落地」作品。現有的 `infra-copilot` 專案已經有 18 個成熟的 runner（`tools/*.py`，150+ 個函式，涵蓋 Zabbix、Wazuh、vSphere、Dell ME、Synology、PPDM、FortiGate、AD、Linux），但目前只是透過 Claude Code 被臨時呼叫，沒有版控、沒有部署機制。

目標不是讓 P660 同事真的採用（那個 ROI 假設還沒驗證），而是把這套工具包成一個**真正跑起來、可演示**的 MCP server，同時展示 AI engineering（MCP 設計、工具整合）跟 Platform/DevOps（容器化、部署、版控）兩種能力。

關鍵決定（已確認）：
- 部署目標：在 10.11.1.x 內網新建一台獨立 VM，跟既有 production VM 分開管理，但同網段可直接連到 Zabbix/Wazuh/vSphere/AD 等系統，**不需要額外 VPN/tunnel**
- Demo client：Claude Desktop 為主（零額外程式碼，最快可演示），有餘力再做一個用 Anthropic SDK + `mcp_servers` 參數的自訂 client 當 stretch goal

## 現有資源盤點（已用程式碼驗證，不是猜測）

- **介面品質已經適合包 MCP**：`tools/*.py` 裡的函式幾乎都是 `get_*()` 命名、回傳結構化 dict/list、有中文 docstring。grep 全部 `tools/` 後唯一的寫入型函式是 `secrets.py.set_secret()`（管理用，不開放）。
- **`tools/secrets.py.get()` 其實已經跨平台**：目前的程式碼是「Keychain 讀不到就 fallback 到 `os.getenv()`」，不需要改 code。只要部署機的 `.env` 裡放對應的值就能正常運作；`set_secret()`（寫入 Keychain）在 Linux 上不能用，但部署機本來就不需要跑它。
- **需要登入拿 token 的 runner**：`zabbix_runner.login()`、`wazuh_runner.login()`、`ppdm_runner.login()`、`synology_runner.login()` / `login_host()`、`fortigate_runner.login()`。這些回傳的 token/session 要在 MCP server 內部快取，不能讓 LLM 自己管理 token。
- **不需要 token 的**：`linux_runner.py`（每次呼叫自己開 SSH）、`vsphere_runner.py`、`dell_me_runner.py`（用既有連線方式）。
- **危險的底層 primitive，絕對不能包成 MCP tool**：`linux_runner.ssh(host, cmd)` 和 `ssh_runner.py` 是任意命令執行函式，只能包上層的 `get_system_info`/`get_disk` 等具體函式。
- **MCP Python SDK 確認可用**：官方 `mcp` package 提供 `FastMCP`，用 `@mcp.tool()` decorator 包函式，`mcp.run(transport="streamable-http")` 跑成 remote server（這部分已用 WebFetch 核對官方 README，不是憑記憶猜的）。

## 架構總覽

```
Claude Desktop (Hank 的筆電)
        │  Streamable HTTP + Bearer token
        ▼
10.11.1.x 新 VM (Docker container)
        │
        ├── mcp_server/server.py        ← FastMCP 主程式，註冊 ~18-20 個唯讀 tool
        ├── mcp_server/session_cache.py ← 通用 token/session 快取
        └── 呼叫既有 tools/*.py 的 get_* 函式
                │
                ▼
   Zabbix / Wazuh / vSphere / PPDM / Synology / Linux SSH / AD / Dell ME / FortiGate
   （同網段直連，不需要 VPN）
```

## Phase 0：VM 準備（Hank 自行操作，非工程階段）

- 在 10.11.1.x 建一台新 Ubuntu VM，裝 Docker（不需要 join AD，這是單一用途的 service VM，跟現有「Ubuntu 24.04 + join AD」SOP 是給一般伺服器用的，這台不必套用全套）
- 確認防火牆只允許 Hank 的來源 IP（筆電/辦公網段）連到這台 VM 的 MCP port，避免內網其他人隨意打到這個服務

## Phase 1：基礎工程（約 1 週）

- `git init`，先補一個 `.gitignore`（確認已涵蓋 `.env`、`__pycache__/`、`*.pyc`），然後做漸進式 commit（按功能分批 commit，不要一次性 mega-commit）
- 新增 `requirements.txt`，鎖定現有用到的套件版本（`paramiko`、`requests`、`pyyaml`、`python-dotenv`、`keyring`、`flask` 等）+ 新增 `mcp`、`anthropic`
- 不需要改 `tools/secrets.py` 的程式碼。部署機操作：在新 VM 上建立 `.env`（`chmod 600`），填入 MCP server 會用到的密碼（Zabbix/Wazuh/PPDM/Synology/FortiGate/LDAP），不進 git

## Phase 2：MCP Server 本體（約 2-3 週）

新增 `mcp_server/` 目錄：

- **`mcp_server/session_cache.py`**：通用快取工具，簽名類似：
  ```python
  def get_token(name: str, login_fn, ttl: int = 300):
      # 命中快取且未過期就回傳，否則呼叫 login_fn() 重新登入並快取
  ```
  每個需要登入的系統呼叫 `get_token("zabbix", zabbix_runner.login)` 取得 token，避免每次 tool call 都重新登入。

- **`mcp_server/server.py`**：`FastMCP` 主程式，用 `@mcp.tool()` 包以下唯讀函式（起始清單，之後可再擴充）：

  | 系統 | 函式（來自既有 `tools/*.py`） |
  |---|---|
  | Zabbix | `get_problems`, `get_host_availability`, `get_disk_growth` |
  | Wazuh | `get_agent_summary`, `get_agent_issues`, `get_service_health` |
  | vSphere | `get_all_vms`, `get_datastores`, `get_active_alarms`, `get_recent_events` |
  | PPDM | `get_backup_summary`, `get_failed_jobs` |
  | Synology | `get_nas_list`, `get_backup_status` |
  | Linux | `get_system_info`, `get_load`, `get_disk`, `get_memory` |
  | AD | `get_locked_accounts`, `get_expiring_passwords` |
  | Dell ME | `get_disk_summary`, `get_all_system_info` |
  | FortiGate | `get_system_status`, `get_interfaces` |

  每個 MCP tool 的 docstring 要寫清楚「什麼時候該呼叫」（觸發條件），不是只說功能 — 這會直接影響 Claude 在 demo 時選工具的準確度。

- **存取控制**：第一版先靠網路層（VM 只在內網、防火牆限制來源 IP，見 Phase 0），不用一開始就上完整 OAuth。如果要加一層應用層防護，用 `mcp.streamable_http_app()` 拿到 Starlette app 後包一個簡單的自訂 middleware，檢查固定的 `Authorization: Bearer <shared-secret>`，比照搬官方 `TokenVerifier`/`AuthSettings`（那套預設假設有完整 OAuth issuer，對這個規模太重）。

- **本機開發迴圈**：先用 `transport="stdio"` 在本機快速迭代、用 Claude Desktop 本機測試工具是否被正確呼叫，最後才切到 `transport="streamable-http"` 部署。

## Phase 3：容器化 + 部署（約 1-2 週）

- 寫 `Dockerfile`（`python:3.12-slim` base，裝 `requirements.txt`）
- 寫 `docker-compose.yml`（mount `.env`、開 port，方便本機和 VM 上都用同一份設定跑）
- 部署到 Phase 0 準備好的 VM：`docker compose up -d`，外加一個 systemd unit 包一層確保開機自動啟動、掛掉自動重啟
- 簡單的 GitHub Actions（lint + `python -c "import mcp_server.server"` 之類的 smoke import test）。**Repo 設為 private** —— 這個專案會直接碰公司真實 IP/帳號慣例/系統架構，不適合公開。

## Phase 4：Demo + 文件（最後幾天）

- README：架構圖（沿用上面的文字圖即可）、為什麼選 MCP、怎麼跑起來、怎麼測試
- Claude Desktop 設定範例：連到這台 VM 的 streamable-http endpoint（精確的設定檔語法在實作階段要對照當下 Claude Desktop 版本的文件確認，目前各版本對 remote MCP 的支援方式有差異，不要直接照抄這份 plan 裡的猜測語法）
- 準備 3-5 個面試 demo 用的問題（例如「現在有哪些 Zabbix 高優先度問題還沒解？」「vSphere 有哪些 datastore 快滿了？」）
- Stretch goal（時間允許再做）：用 Anthropic SDK 的 `mcp_servers` 參數寫一個最小的自訂 client，展示自己接 Messages API 的能力，不只是設定現成的 Claude Desktop

## 公開／分享注意事項

這個 repo 因為會直接呼叫公司正式系統、含真實 IP 與帳號慣例，**不應該公開上傳到公開 GitHub**。面試展示建議用「live demo + 架構說明」，repo 維持 private。如果之後想要一份可以公開分享的版本，建議在這個專案穩定後，另外整理一份把公司專屬細節（IP、hostname、帳號命名）替換成範例值的「reference architecture」版本，而不是把現在這份直接公開。

## 驗證方式

1. **本機**：`python3 -m mcp_server.server`（stdio transport）+ 直接用 Python 測試腳本呼叫每個 tool，確認回傳資料正確、token 快取有作用（連續呼叫同一個系統不會每次都重新登入）
2. **部署後**：在 VM 上 `docker compose up -d`，從 Hank 的筆電用 `curl` 打 health check endpoint 確認服務有起來
3. **端對端**：Claude Desktop 連上這台 VM 的 MCP server，問 Phase 4 準備的 demo 問題，確認 Claude 選對 tool、回傳資料跟直接跑 `tools/*.py` 一致
4. **安全檢查**：確認沒開 bearer token 防護時，至少網路層的來源 IP 限制有生效（從非允許的 IP 連不過去）

## 進度追蹤

對應 Claude Code 內的 Task 清單（Phase 0-4，已設好依賴關係）。下次接續時可以直接問「現在進度到哪」或參考 memory 裡的 `project_internal_ai_packaging`。
