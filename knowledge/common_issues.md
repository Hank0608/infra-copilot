# Knowledge Base — Common Infra Issues & SOPs

---

## KB-001: RP 監聽埠衝突導致外網 500（未進入 Ingress）

**症狀**
- 外部 `curl -I https://<domain>` 回傳 `500 Internal Server Error`
- K8s Ingress Controller log 在事件時間窗口內**無任何請求記錄**
- K8s Pod readiness probe 全部正常
- 內部 health check 無異常

**根因**
Nginx server block 的 `listen` 指令綁定到非標準埠（常見：8000、8080），
而外部 load balancer / firewall 並未將 443 port-forward 至該埠，
導致請求在 RP 層被丟棄並回傳 500，從未到達 Ingress。

**診斷指令**
```bash
# 在 rp-main 上執行
grep -rn "listen" /etc/nginx/sites-available/ | grep -v "listen 443\|listen 80\|listen \[\|#"
nginx -T 2>/dev/null | grep -A5 "server_name.*<domain>"
tail -100 /var/log/nginx/error.log
```

**判定條件**
- 找到 `listen <非80/443埠>` 且對應 `server_name` 包含問題 domain → 確認根因

**修復**
```nginx
server {
    listen 443 ssl;
    server_name <domain>;
    ...
}
```
然後 `nginx -t && nginx -s reload`

---

## KB-002: Ingress 規則遺失或 host header 不符

**症狀**
- RP access log 顯示請求已正常 proxy upstream
- 回傳 `404 Not Found` 或 nginx 預設頁面
- K8s Ingress log 有請求但無匹配規則

**根因**
Ingress resource 的 `host` 欄位與實際請求的 Host header 不符，
或 Ingress resource 被誤刪 / 部署到錯誤 namespace。

**診斷指令**
```bash
kubectl get ingress -A
kubectl describe ingress <name> -n <namespace>
```

**判定條件**
- `host` 欄位與 domain 不符 → 更新 Ingress resource

---

## KB-003: Pod CrashLoopBackOff 導致 502/503

**症狀**
- RP 和 Ingress 均正常，但回傳 `502 Bad Gateway` 或 `503 Service Unavailable`
- Ingress log 顯示 `upstream connect error` 或 `no live upstreams`

**根因**
後端 Pod 反覆重啟（CrashLoopBackOff）或 Readiness probe 失敗，
Service Endpoint 無健康成員可接收流量。

**診斷指令**
```bash
kubectl get pods -n <namespace>
kubectl describe pod <pod-name> -n <namespace>
kubectl logs <pod-name> -n <namespace> --previous
```

**判定條件**
- `RESTARTS` 計數持續增加 → 查 pod log 找 crash 根因

---

## KB-004: 診斷 SOP — proxy_pass 指向 domain 時先查 DNS

**情境**
看到 nginx `proxy_pass https://<domain>` 時，不可直接斷定是 proxy loop。

**正確步驟**
```bash
# 在 rp-main 上執行，確認 domain 在內部解析到哪裡
nslookup <domain>
```

**判定**
- 解析到 K8s Ingress IP (10.11.1.236) → 正常，請求會送到 Ingress
- 解析到 RP 自身 IP (10.11.9.2) → 真正的 proxy loop，需修正 proxy_pass 目標

**判定補充**
- 解析到其他後端 IP（例如 10.11.1.233）→ 正常，proxy_pass 會打到該後端
- 不只 Ingress，AD DNS 可將 domain 指向任何內部 IP，不可用「不是 Ingress IP 就有問題」來判斷

**教訓來源**
- 2026-04-28：診斷 recruitment.ubiqconn.com 時未查 DNS，誤判 proxy_pass 為 loop
- 2026-04-29：看到 www-test.conf 的 proxy_pass 指向自身域名，再度未先 nslookup 就懷疑是迴圈。實際解析到 10.11.1.233，完全正常。

---

## KB-008: nslookup 通但 ping/curl 失敗 — DNS 快取不一致

**症狀**
- `nslookup <domain>` 回傳新 IP（正確）
- `ping <domain>` 或連線失敗（仍打到舊 IP）

**根因**
`nslookup` 直接查 DNS server，繞過本機快取。
`ping` / `curl` / 瀏覽器使用 OS DNS 快取，可能還記著舊 record。
常發生在 DNS 切換後（例如服務遷移到 K8s 後更新 A record）。

**修復：清除 DNS 快取**
```bash
# Windows
ipconfig /flushdns

# macOS
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

# Linux (systemd-resolved)
sudo resolvectl flush-caches
```

**補充：ping 不通不代表服務掛了**
K8s Worker / Server Farm 防火牆通常擋 ICMP，ping 永遠不通但 HTTP 正常。
驗證服務用 `curl -k https://<domain> -I` 才準確。

---

## KB-005: 對外服務上線標準流程（MIS SOP）

**完整步驟**

**Step 1 — 內部 DNS（AD DNS）**
- AD DNS Manager → ubiqconn.com zone → 新增 A Record 指向後端服務內部 IP
- 在 rp-main 驗證：`nslookup <service>.ubiqconn.com`（應回傳內部 IP）

**Step 2 — 外部 DNS**
- eDNS 新增 A Record：`<service>.ubiqconn.com A 61.220.184.189`（Forti 公網 IP）
- 若為自架 BIND9：`vi /etc/bind/zones/db.ubiqconn.com && systemctl restart bind9`

**Step 3 — 防火牆**
- WAN → DMZ：確認 Public IP:443 → rp-main (10.11.9.x):443 VIP 存在
- DMZ → Server Farm：rp-main → 後端 IP:port，Action ACCEPT

**Step 4 — Nginx 設定（標準範本）**
```nginx
# /etc/nginx/sites-available/<service>.conf
server {
    listen *:443 ssl;
    server_name <service>.ubiqconn.com;
    ssl_certificate /var/www/ubiqconn/cert.chain.crt;
    ssl_certificate_key /var/www/ubiqconn/www_ubiqconn_com.key;
    location / {
        proxy_pass https://<service>.ubiqconn.com;
    }
}
# 若服務需要 :8000（舊架構，K8s 後通常不需要）
server {
    listen *:8000;
    server_name <service>.ubiqconn.com;
    location / {
        proxy_pass https://<service>.ubiqconn.com:8000;
    }
}
```
注意：rp-main 的 `nginx.conf` 使用 `include /etc/nginx/sites-available/*`，
所有 sites-available 下的 conf 都是 active，不需要建 symlink 到 sites-enabled。

**Step 5 — 測試**
```bash
nginx -t
systemctl reload nginx
curl -k https://<service>.ubiqconn.com -I
```

---

## KB-006: SSL 憑證更新 SOP

**憑證檔案**
- 統一命名：`ubiqconn.crt` / `ubiqconn.key`
- rp-main 憑證路徑：`/var/www/ubiqconn/cert.chain.crt` + `www_ubiqconn_com.key`
- 後端服務標準路徑：`/var/www/cert/`

**後端服務 IP 清單（ubiqconn 系列）**

| IP | 服務 |
|----|------|
| 10.11.1.159 | CRM |
| 10.11.1.163 | OKR |
| 10.11.1.167 | recruitment |
| 10.11.1.171 | GSS |
| 10.11.1.172 | punch-in |
| 10.11.1.175 | PMS |
| 10.11.1.176 | legal |
| 10.11.1.181 | online-exam |
| 10.11.1.192 | customs-invoice |
| 10.11.1.196 | harbor |
| 10.11.1.199 | start |
| 10.11.1.114 | ubiq-srm |
| 10.11.1.212 | np_info |

**Ruggon 系列**

| IP | 服務 |
|----|------|
| 10.11.1.160 | snquery |
| 10.11.1.185 | dev-iot |
| 10.11.1.186 | dev-frontend-api |
| 10.11.1.188 | dev-device-api |
| 10.11.1.194 | partner-zone |

**更新步驟**
```bash
# 1. 備份（必做）
sudo mkdir -p /var/www/cert/backup_$(date +%Y%m%d)
sudo cp /var/www/cert/* /var/www/cert/backup_$(date +%Y%m%d)/

# 2. 移入新憑證（先上傳至 /home/ubiqconn/）
sudo mv /home/ubiqconn/ubiqconn.crt /var/www/cert/
sudo mv /home/ubiqconn/ubiqconn.key /var/www/cert/

# 3. 設定權限
sudo chown root:root /var/www/cert/ubiqconn.*
sudo chmod 600 /var/www/cert/ubiqconn.key
sudo chmod 644 /var/www/cert/ubiqconn.crt

# 4. 重啟前先測試
sudo nginx -t
sudo systemctl reload nginx

# 5. 驗證
openssl x509 -in /var/www/cert/ubiqconn.crt -noout -dates
```

**Roll back**
```bash
sudo cp /var/www/cert/backup_YYYYMMDD/* /var/www/cert/
sudo systemctl reload nginx
```

---

## KB-009: DNS 健診方法論

**判斷流量是否真實有效**
1. Cloud DNS 查詢數 → 有沒有人在查這筆記錄
2. GCP LB Log Explorer → `httpRequest.remoteIp` 判斷來源：
   - `10.x.x.x` → GCP 內部服務互呼
   - 公網 IP → 真實外部設備
3. 交叉比對業務狀態 → 有查詢不代表有業務用途（殭屍流量：程式仍在 call 但服務已停用）

**外部 Cloud DNS vs 內部 AD DNS**
- 兩者可能指向不同 IP，診斷時要分別查
- `nslookup` 從 rp-main 下 → 查到的是 AD DNS 的解析結果

---

## KB-010: 廢棄服務完整清理清單

一個服務真正清乾淨，需處理以下所有項目：

| 項目 | 說明 |
|------|------|
| Cloud DNS 記錄 | 刪除對應 A / CNAME 記錄 |
| AD DNS 記錄 | 內部解析，需另外在 AD DNS Manager 刪除 |
| rp-main nginx config | 對應 server block 刪除或註解 |
| 防火牆 VIP / port forward | 刪除對外 NAT 規則 |
| GCP / 雲端專案 | 確認可關閉後刪除，停止計費 |
| Zabbix host / agent | disable 或 delete 監控中對應的 host，避免誤報 |

**注意**：nginx backup 檔不能放在 `sites-available/` 目錄，該目錄下所有檔案都會被 include，會造成重複 server_name 衝突。

---

## KB-011: nginx sudo 寫檔（Paramiko 無互動環境）

**情境**：透過 SSH 修改 `/etc/nginx/` 下需要 sudo 的設定檔

**正確流程**
```python
# 1. 將新內容寫到 home 目錄 temp file（不需要 sudo）
sftp.open('/home/user/file.tmp', 'w').write(new_content)

# 2. sudo cp temp → 目標路徑
client.exec_command(f'echo {passwd} | sudo -S cp /home/user/file.tmp /etc/nginx/sites-available/target')

# 3. 刪 temp
client.exec_command('rm /home/user/file.tmp')

# 4. 語法檢查 + reload
client.exec_command(f'echo {passwd} | sudo -S nginx -t')
client.exec_command(f'echo {passwd} | sudo -S nginx -s reload')
```

**注意**：`sudo tee` 搭配 get_pty 在某些環境下無法正確接收 stdin，用 `cp` 更穩定。

---

## KB-012: 502 Bad Gateway 實為應用程式層 404 — 官網前端語系缺失

**症狀**
- 官網前端特定頁面顯示 `502 Bad Gateway`
- 其他頁面正常

**診斷過程**
1. 看到 502 先懷疑 Pod crash 或 upstream 不通
2. 實際查 K8s application log → 回傳的是 `404 Not Found`
3. Nginx 把後端的 404 包裝成 502 回給前端（upstream 有回應但回傳錯誤碼）
4. 看 code → 發現該頁面未實作中文語系（zh-TW），語系路由找不到對應資源

**根因**
前端框架的語系路由（i18n）缺少中文語系設定，訪問中文路徑時後端回 404，
Nginx upstream 收到非 2xx/3xx 回應後以 502 呈現給使用者。

**診斷指令**
```bash
# 1. 先確認 K8s Pod 是否正常
kubectl get pods -n ubiqconn

# 2. 看 application log（找真正的 error code）
kubectl logs <pod-name> -n ubiqconn --tail=50

# 3. 也可從 Nginx access log 看 upstream status
grep '<domain>' /var/log/nginx/access.log | tail -20
```

**教訓**
- **502 不一定是 Pod 掛了**，也可能是 Pod 正常運行但回傳 4xx/5xx
- 看到 502 的下一步是查 **K8s application log**，找 upstream 真正回傳的 status code
- 502 是 Nginx 的包裝，實際錯誤要從後端 log 判斷

**VCSA 資訊**
- IP: `10.11.1.15`
- VAMI: `https://10.11.1.15:5480/`
- SSO 帳號: `administrator@utivcenter2.ubiqconn.com`

**步驟**
1. 登入 VAMI → 左側「存取權」→「編輯」→ 啟用 SSH + Bash Shell
2. SSH 連線到 `10.11.1.15`，以 SSO admin 登入
3. 進入 bash：`shell`
4. 重設密碼：`sudo passwd root`
5. 解鎖帳號：`sudo passwd -u root`
6. 確認狀態：`sudo chage -l root`（確認 Password expires 已更新）

---

## KB-013: Windows Port 占用診斷 SOP

**症狀**
- 應用程式啟動失敗，錯誤訊息為「port 已被占用」
- `netstat -ano | findstr :<port>` 無結果
- 廠商說「被系統程式占用，需要重開機」

**診斷步驟（依序執行）**

**Step 1 — 確認是否真的有 process 在監聽**
```cmd
netstat -ano | findstr :<port>
```
有結果 → 看最後欄位的 PID，執行 Step 4。
沒結果 → 繼續 Step 2。

**Step 2 — 確認是否被 OS 保留（Port Reservation）**
```cmd
netsh int ipv4 show excludedportrange protocol=tcp
```
port 在範圍內 → 是 Hyper-V / Container 動態保留問題，見修復方案。
沒在範圍內 → 繼續 Step 3。

**Step 3 — 直接嘗試 bind（最終驗證）**
```powershell
$port = <PORT>
$tryListen = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
try {
    $tryListen.Start()
    Write-Host "Port $port 空著，系統沒有鎖死" -ForegroundColor Green
    Start-Sleep -Seconds 10
    $tryListen.Stop()
} catch {
    Write-Host "監聽失敗：$($_.Exception.Message)" -ForegroundColor Red
}
```
綠色 → port 完全空著，問題在應用程式本身的啟動邏輯，要查服務 log。
紅色 → 確認被占，執行 Step 4。

**Step 4 — 查兇手**
```powershell
Get-NetTCPConnection -LocalPort <port> |
Select-Object LocalPort, State, OwningProcess,
  @{n="Process";e={(Get-Process -Id $_.OwningProcess).Name}}
```

**修復方案（Port Reservation 問題）**

方法一：幫應用程式預留 port（不需重開機）
```cmd
netsh int ipv4 add reservedport protocol=tcp startport=<port> numberofports=1
```
然後重啟服務即可。

方法二：把 dynamic port range 移走（需重開機）
```cmd
netsh int ipv4 set dynamicport tcp start=60000 num=5535
```

**注意**
- `netstat` 只看得到 LISTENING / ESTABLISHED 狀態，抓不到 port reservation。
- Step 3 的 TcpListener 腳本是最準確的驗證，直接觸發 OS bind()。
- Step 3 綠色但服務仍無法啟動 → 去查服務的 Windows Event Log 或應用程式 log，不是 port 問題。
- 廠商建議「重開機解決 port 占用」：重開機會重新分配 dynamic range，有機會解決但不保證，應使用 `reservedport` 根治。
