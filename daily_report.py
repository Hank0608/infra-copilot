"""每日晨報 — AD + PPDM + Synology + Dell ME 整合摘要。"""

import datetime
import json
import os
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dotenv import load_dotenv
from tools import wazuh_runner    as wz
from tools import ad_runner       as ad
from tools import ppdm_runner     as ppdm
from tools import synology_runner as syno
from tools import dell_me_runner  as me
from tools import fortigate_runner as fw

load_dotenv(Path(__file__).parent / ".env")

TODAY         = datetime.date.today().strftime("%Y-%m-%d")
WARN_PWD_DAYS = 14
TEAMS_URL     = os.getenv("TEAMS_WEBHOOK_URL", "")

SMTP_HOST     = os.getenv("SMTP_HOST", "10.11.1.125")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "25"))
EMAIL_FROM    = "infra-alerts@ubiqconn.com"
EMAIL_TO      = "hank_lin@ubiqconn.com"


# ── 資料收集 ──────────────────────────────────────────────

def _collect() -> dict:
    result = {"errors": [], "ad": {}, "ppdm": {}, "synology": {}, "dell_me": {}, "fortigate": {}}

    try:
        expiring = ad.get_expiring_passwords(days=WARN_PWD_DAYS)
        result["ad"] = {"expiring": expiring}
    except Exception as e:
        result["errors"].append(f"AD: {e}")

    try:
        lockouts      = wz.get_dc_lockouts(hours=24)
        logon_summary = wz.get_dc_logon_failure_summary(hours=24)
        result["ad_security"] = {
            "lockouts":      lockouts,
            "logon_summary": logon_summary,
        }
    except Exception as e:
        result["errors"].append(f"AD Security: {e}")

    try:
        with ppdm._token() as t:
            storage     = ppdm.get_storage(t)
            ppdm_alerts = ppdm.get_alerts(t, severity="CRITICAL", limit=10)
            core_run    = ppdm.get_policy_run(t, "Core Service")
        result["ppdm"] = {
            "core_run": core_run,
            "storage":  storage,
            "alerts":   ppdm_alerts,
        }
    except Exception as e:
        result["errors"].append(f"PPDM: {e}")

    try:
        with syno._session() as sid:
            backups = syno.get_backup_status(sid)
            cameras = syno.get_cameras(sid)
        now8     = __import__("datetime").datetime.now(tz=syno._TZ8)
        cutoff30 = now8 - __import__("datetime").timedelta(days=30)
        result["synology"] = {
            "backups": backups,
            "cameras": cameras,
            "ok":      sum(1 for b in backups if b["last_status"] == 3),
            "warn":    sum(1 for b in backups if b["last_status"] not in (3, None)),
            "no_bk":   sum(1 for b in backups if b["last_status"] is None),
            "stale":   [b for b in backups if b["is_scheduled"] and (not b["last_time"] or b["last_time"] < cutoff30)],
            "cam_ok":  sum(1 for c in cameras if c.get("status") == 1),
        }
    except Exception as e:
        result["errors"].append(f"Synology: {e}")

    try:
        result["fortigate"] = fw.get_report_data()
    except Exception as e:
        result["errors"].append(f"FortiGate: {e}")

    try:
        me_data  = me.get_all_hosts(hours=24)
        all_sets = me.dedup_sets(me_data)
        all_peers= [p for d in me_data.values() for p in d["peers"]]
        all_errs = [e for d in me_data.values() for e in d["events"]
                    if e["severity"] in ("ERROR", "CRITICAL")]
        failed_hosts = [h for h, d in me_data.items() if d["error"]]
        all_runs = me.dedup_runs(me_data)
        result["dell_me"] = {
            "hosts":      me_data,
            "rep_sets":   all_sets,
            "peers":      all_peers,
            "err_events": all_errs,
            "runs":       all_runs,
            "all_ok":     all(r["last_run_num"] == 1 for r in all_sets),
            "peer_ok":    all(p["status_num"] == 1 for p in all_peers),
            "failed_hosts": failed_hosts,
        }
    except Exception as e:
        result["errors"].append(f"Dell ME: {e}")

    return result


# ── 純文字報告 ────────────────────────────────────────────

def run(full: bool = False) -> str:
    d      = _collect()
    lines  = ["=" * 60, f"  每日晨報  {TODAY}", "=" * 60]

    # AD
    lines.append("\n【AD 密碼到期預警】")
    if "expiring" in d["ad"]:
        expiring = d["ad"]["expiring"]
        overdue = [u for u in expiring if u["daysLeft"] < 0]
        urgent  = [u for u in expiring if 0 <= u["daysLeft"] <= 3]
        recent  = [u for u in overdue if u["daysLeft"] >= -90]
        lines.append(f"  已到期：{len(recent)} 筆｜3 天內到期：{len(urgent)} 筆")
        for u in recent:
            lines.append(f"  🔴 {u['displayName']}  {u['department'][:25]}  ({abs(u['daysLeft'])} 天前)")
        for u in urgent:
            lines.append(f"  🟠 {u['displayName']}  {u['department'][:25]}  剩 {u['daysLeft']} 天")
    else:
        lines.append("  ⚠️  無法取得")

    # AD 異常登入
    lines.append("\n【AD 異常登入】")
    if "lockouts" in d.get("ad_security", {}):
        sec       = d["ad_security"]
        lockouts  = sec["lockouts"]
        summary   = sec["logon_summary"]
        total_fail = summary.get("total", 0)

        # 鎖定
        if lockouts:
            lines.append(f"  🔴 帳號鎖定（24h）：{len(lockouts)} 筆")
            for lk in lockouts:
                lines.append(f"    {lk['target_user']}  {lk['ts']}")
        else:
            lines.append("  ✅ 無帳號鎖定")

        # 登入失敗 top — 僅列超過 20 次的
        high_fail = [(u, c) for u, c in summary.get("by_user", []) if c >= 20]
        if high_fail:
            lines.append(f"  🟠 登入失敗（24h）：共 {total_fail} 筆，異常帳號：")
            for u, c in high_fail:
                lines.append(f"    {u:<25} {c} 次")
        else:
            lines.append(f"  ✅ 登入失敗（24h）：共 {total_fail} 筆，無異常")
    else:
        lines.append("  ⚠️  無法取得")

    # PPDM
    lines.append("\n【PPDM 備份】")
    if "core_run" in d["ppdm"]:
        cr      = d["ppdm"]["core_run"]
        storage = d["ppdm"]["storage"]
        alerts  = d["ppdm"]["alerts"]
        if cr:
            ok_icon = "✅" if cr["status"] == "OK" else ("🟡" if cr["status"] == "OK_WITH_ERRORS" else "❌")
            gid     = cr["group"]["id"][:8].upper()
            lines.append(f"  {ok_icon} Core Service — {cr['type']}  {cr['start']}  {cr['ok']}/{cr['total']} VM  [Job: {gid}]")
            for v in cr["vms"]:
                icon = "✅" if v["status"] == "OK" else ("🟡" if v["status"] == "OK_WITH_ERRORS" else "❌")
                lines.append(f"    {icon} {v['name']:<40}  {v['end']}")
        else:
            lines.append("  ⚠️  Core Service 無近期備份紀錄")
        for st in storage:
            if st["type"] == "DATA_DOMAIN_SYSTEM":
                util = st["utilization"]
                icon = "🔴" if util >= 85 else ("🟡" if util >= 70 else "✅")
                lines.append(f"  {icon} {st['name']}：{st.get('used_tb',0):.1f} TB / {st.get('total_tb',0):.1f} TB ({util:.0f}%)  壓縮 {st.get('compression',0):.1f}x")
        if alerts:
            for a in alerts[:3]:
                t_ = str(a.get("postedTime",""))[:16].replace("T"," ")
                lines.append(f"  🚨 [{t_}] {a.get('message','')[:65]}")
    else:
        lines.append("  ⚠️  無法取得")

    # Synology
    lines.append("\n【Synology ABB 備份】")
    if "backups" in d["synology"]:
        sy = d["synology"]
        ok_icon = "✅" if sy["warn"] == 0 and sy["stale"] == [] else "⚠️"
        lines.append(f"  {ok_icon} 備份任務：{len(sy['backups'])} 個｜✅ {sy['ok']}  ⚠️ {sy['warn']}  ⬜ {sy['no_bk']}")
        for b in sy["stale"]:
            lt = syno._fmt_dt(b["last_time"], "從未")
            lines.append(f"  ⚠️ {b['name'][:40]}  最後:{lt}（超過30天）")
        cam_total = len(sy["cameras"])
        cam_warn  = cam_total - sy["cam_ok"]
        lines.append(f"  {'✅' if cam_warn == 0 else '❌'} 監視器：{cam_total} 台  正常 {sy['cam_ok']}  異常 {cam_warn}")
    else:
        lines.append("  ⚠️  無法取得")

    # FortiGate
    lines.append("\n【FortiGate 防火牆】")
    if d["fortigate"].get("ha"):
        fg = d["fortigate"]
        # HA
        ha_ok = all(m["uptime_days"] > 0 for m in fg["ha"])
        ha_str = "  ".join(f"{m['hostname']} cpu={m['cpu']}% mem={m['mem']}% uptime={m['uptime_days']}d" for m in fg["ha"])
        lines.append(f"  {'✅' if ha_ok else '❌'} HA：{ha_str}")
        # Firmware
        cur = fg["firmware"].get("current", "")
        avail = fg["firmware"].get("available", [])
        fw_icon = "🟡" if avail else "✅"
        fw_str  = f"{cur}  {'→ 可更新：' + ', '.join(avail[:2]) if avail else '已是最新'}"
        lines.append(f"  {fw_icon} Firmware：{fw_str}")
        # VPN
        down = [t for t in fg["tunnels"] if not t["up"]]
        up   = [t for t in fg["tunnels"] if t["up"]]
        lines.append(f"  {'✅' if not down else '❌'} IPsec VPN：{len(up)} 條正常  {len(down)} 條斷線")
        for t in down:
            lines.append(f"    ❌ {t['name']}")
        for t in up:
            lines.append(f"    ✅ {t['name']}  rx={t['rx_gb']} GB  tx={t['tx_gb']} GB")
    else:
        lines.append("  ⚠️  無法取得")

    # Dell ME
    lines.append("\n【Dell ME 複製】")
    if "hosts" in d["dell_me"]:
        dm = d["dell_me"]
        ok_icon = "✅" if dm["all_ok"] and dm["peer_ok"] and not dm["failed_hosts"] else "❌"
        total   = len(dm["rep_sets"])
        ok_cnt  = sum(1 for r in dm["rep_sets"] if r["last_run_num"] == 1)
        lines.append(f"  {ok_icon} {len(me.ME_HOSTS)} 台｜Replication {ok_cnt}/{total} 成功  Peer {'✅全線上' if dm['peer_ok'] else '❌有斷線'}")
        if dm["failed_hosts"]:
            for h in dm["failed_hosts"]:
                lines.append(f"  ❌ {h} 連線失敗：{dm['hosts'][h]['error']}")
        # 複製歷程
        for set_name, runs in sorted(dm["runs"].items()):
            lines.append(f"  📋 {set_name}")
            by_host = {}
            for r in runs:
                by_host.setdefault(r["host"], []).append(r)
            for host, hruns in sorted(by_host.items()):
                for r in hruns[:2]:
                    icon = "✅" if r["result"] == "OK" else "❌"
                    st   = r["start"].strftime("%m/%d %H:%M") if r["start"] else "—"
                    end  = r["end"].strftime("%H:%M") if r["end"] else "執行中"
                    dur  = me._fmt_dur(r["dur_min"])
                    gb   = f"  {r['data_gb']:.1f} GB" if r.get("data_gb") else ""
                    lines.append(f"    {icon} {host}  {r['state']:11s}  {st} → {end}  ({dur}){gb}")
        if dm["err_events"]:
            lines.append("  近24h 錯誤：")
            for e in dm["err_events"][:3]:
                t = e["time"].strftime("%m/%d %H:%M") if e["time"] else "—"
                lines.append(f"    ❌ [{t}] {e['host']}  {e['message'][:55]}")
    else:
        lines.append("  ⚠️  無法取得")

    lines.append("\n" + "=" * 60)
    if d["errors"]:
        lines.append(f"⚠️  失敗來源：{', '.join(d['errors'])}")
    else:
        lines.append("✅  AD / PPDM / Synology / Dell ME 均正常")
    lines.append("=" * 60)
    return "\n".join(lines)


# ── Adaptive Card ─────────────────────────────────────────

def _tb(text: str, size: str = "Default", weight: str = "Default",
        color: str = "Default", wrap: bool = True) -> dict:
    b = {"type": "TextBlock", "text": text, "wrap": wrap}
    if size    != "Default": b["size"]   = size
    if weight  != "Default": b["weight"] = weight
    if color   != "Default": b["color"]  = color
    return b


def _fact(title: str, value: str) -> dict:
    return {"title": title, "value": value}


def build_card() -> dict:
    d      = _collect()
    body   = []

    # ── Header ─────────────────────────
    body.append(_tb(f"📋 每日晨報  {TODAY}", size="Large", weight="Bolder"))
    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── AD ─────────────────────────────
    body.append(_tb("🔑 AD 密碼到期預警", weight="Bolder", color="Accent"))
    if "expiring" in d["ad"]:
        expiring = d["ad"]["expiring"]
        overdue  = [u for u in expiring if u["daysLeft"] < 0]
        urgent   = [u for u in expiring if 0 <= u["daysLeft"] <= 3]
        recent   = [u for u in overdue if u["daysLeft"] >= -90]

        facts = [
            _fact("已到期（90天內）", f"{len(recent)} 筆"),
            _fact("3 天內到期",       f"{len(urgent)} 筆"),
        ]
        body.append({"type": "FactSet", "facts": facts})

        for u in recent:
            body.append(_tb(f"🔴 {u['displayName']}（{u['department'][:20]}）已過期 {abs(u['daysLeft'])} 天", color="Attention"))
        for u in urgent:
            body.append(_tb(f"🟠 {u['displayName']}（{u['department'][:20]}）剩 {u['daysLeft']} 天", color="Warning"))
    else:
        body.append(_tb("⚠️ 無法取得 AD 資料", color="Attention"))

    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── AD 異常登入 ─────────────────────
    body.append(_tb("🔐 AD 異常登入", weight="Bolder", color="Accent"))
    if "lockouts" in d.get("ad_security", {}):
        sec      = d["ad_security"]
        lockouts = sec["lockouts"]
        summary  = sec["logon_summary"]
        total_fail = summary.get("total", 0)
        high_fail  = [(u, c) for u, c in summary.get("by_user", []) if c >= 20]

        facts = [
            _fact("帳號鎖定（24h）", f"{'🔴 ' + str(len(lockouts)) + ' 筆' if lockouts else '✅ 無'}"),
            _fact("登入失敗（24h）", f"{total_fail} 筆" + (f"  ⚠️ {len(high_fail)} 帳號異常" if high_fail else "  ✅ 正常")),
        ]
        body.append({"type": "FactSet", "facts": facts})
        for lk in lockouts[:3]:
            body.append(_tb(f"🔴 鎖定：{lk['target_user']}  {lk['ts']}", color="Attention"))
        for u, c in high_fail[:3]:
            body.append(_tb(f"🟠 {u}  {c} 次登入失敗", color="Warning"))
    else:
        body.append(_tb("⚠️ 無法取得", color="Attention"))

    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── PPDM ───────────────────────────
    body.append(_tb("💾 PPDM 備份", weight="Bolder", color="Accent"))
    if "core_run" in d["ppdm"]:
        cr      = d["ppdm"]["core_run"]
        storage = d["ppdm"]["storage"]
        alerts  = d["ppdm"]["alerts"]
        if cr:
            ok_icon = "✅" if cr["status"] == "OK" else ("🟡" if cr["status"] == "OK_WITH_ERRORS" else "❌")
            gid     = cr["group"]["id"][:8].upper()
            facts   = [_fact("Core Service", f"{ok_icon} {cr['type']}  {cr['start']}  {cr['ok']}/{cr['total']} VM  [Job: {gid}]")]
            for st in storage:
                if st["type"] == "DATA_DOMAIN_SYSTEM":
                    util = st["utilization"]
                    icon = "🔴" if util >= 85 else ("🟡" if util >= 70 else "✅")
                    facts.append(_fact("DD 使用率", f"{icon} {st.get('used_tb',0):.1f}/{st.get('total_tb',0):.1f} TB ({util:.0f}%)"))
            body.append({"type": "FactSet", "facts": facts})
            failed_vms = [v for v in cr["vms"] if v["status"] not in ("OK", "OK_WITH_ERRORS")]
            for v in (failed_vms or []):
                body.append(_tb(f"❌ {v['name']}  {v['end']}", color="Attention"))
            if not failed_vms:
                vm_list = "  ".join(v["name"].split("_")[-1] if "_" in v["name"] else v["name"] for v in cr["vms"])
                body.append(_tb(f"VM：{vm_list}", color="Good"))
        for a in alerts[:2]:
            t_ = str(a.get("postedTime",""))[:16].replace("T"," ")
            body.append(_tb(f"🚨 [{t_}] {a.get('message','')[:65]}", color="Attention"))
    else:
        body.append(_tb("⚠️ 無法取得 PPDM 資料", color="Attention"))

    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── Synology ────────────────────────
    body.append(_tb("💿 Synology ABB 備份", weight="Bolder", color="Accent"))
    if "backups" in d["synology"]:
        sy       = d["synology"]
        cam_warn = len(sy["cameras"]) - sy["cam_ok"]
        facts    = [
            _fact("備份任務", f"✅ {sy['ok']} 成功  ⚠️ {sy['warn']} 警告  ⬜ {sy['no_bk']} 無紀錄"),
            _fact("監視器",   f"{'✅' if cam_warn==0 else '❌'} {sy['cam_ok']}/{len(sy['cameras'])} 正常"),
        ]
        body.append({"type": "FactSet", "facts": facts})
        for b in sy["stale"][:3]:
            lt = syno._fmt_dt(b["last_time"], "從未")
            body.append(_tb(f"⚠️ {b['name'][:35]}  最後備份:{lt}", color="Warning"))
    else:
        body.append(_tb("⚠️ 無法取得 Synology 資料", color="Attention"))

    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── FortiGate ───────────────────────
    body.append(_tb("🔥 FortiGate 防火牆", weight="Bolder", color="Accent"))
    if d["fortigate"].get("ha"):
        fg   = d["fortigate"]
        down = [t for t in fg["tunnels"] if not t["up"]]
        up   = [t for t in fg["tunnels"] if t["up"]]
        avail = fg["firmware"].get("available", [])
        facts = []
        for m in fg["ha"]:
            facts.append(_fact(m["hostname"], f"CPU {m['cpu']}%  MEM {m['mem']}%  {m['sessions']:,} sessions  uptime {m['uptime_days']}d"))
        facts.append(_fact("Firmware", f"{fg['firmware'].get('current','')}{'  🟡 可更新：' + ', '.join(avail[:2]) if avail else '  ✅ 最新'}"))
        facts.append(_fact("IPsec VPN", f"{'✅' if not down else '❌'} {len(up)} 正常  {len(down)} 斷線"))
        body.append({"type": "FactSet", "facts": facts})
        for t in down:
            body.append(_tb(f"❌ VPN 斷線：{t['name']}", color="Attention"))
    else:
        body.append(_tb("⚠️ 無法取得 FortiGate 資料", color="Attention"))

    body.append({"type": "TextBlock", "text": " ", "spacing": "None"})

    # ── Dell ME ─────────────────────────
    body.append(_tb("💽 Dell ME 複製", weight="Bolder", color="Accent"))
    if "hosts" in d["dell_me"]:
        dm    = d["dell_me"]
        ok_cnt = sum(1 for r in dm["rep_sets"] if r["last_run_num"] == 1)
        facts  = [
            _fact("Replication", f"{'✅' if dm['all_ok'] else '❌'} {ok_cnt}/{len(dm['rep_sets'])} 成功"),
            _fact("Peer 連線",   f"{'✅' if dm['peer_ok'] else '❌'} {'全線上' if dm['peer_ok'] else '有斷線'}"),
        ]
        for r in dm["rep_sets"]:
            _, si = me._REP_STATUS.get(r["status_num"], ("?", "❓"))
            ri    = me._RUN_STATUS.get(r["last_run_num"], "❓")
            last  = r["last_success"].strftime("%m/%d %H:%M") if r["last_success"] else "—"
            facts.append(_fact(r["host"], f"{si} {r['name']}  {ri}  {last}"))
        body.append({"type": "FactSet", "facts": facts})
        for e in dm["err_events"][:2]:
            t = e["time"].strftime("%m/%d %H:%M") if e["time"] else "—"
            body.append(_tb(f"❌ [{t}] {e['host']}  {e['message'][:55]}", color="Attention"))
    else:
        body.append(_tb("⚠️ 無法取得 Dell ME 資料", color="Attention"))

    # ── Footer ─────────────────────────
    body.append({"type": "TextBlock", "separator": True,
                 "text": f"{'⚠️ 部分資料源失敗：' + ', '.join(d['errors']) if d['errors'] else '✅ 所有資料源正常（AD/PPDM/Synology/FortiGate/Dell ME）'}",
                 "isSubtle": True, "size": "Small"})

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }


def send_to_teams(url: str = None) -> bool:
    webhook = url or TEAMS_URL
    if not webhook:
        print("未設定 TEAMS_WEBHOOK_URL")
        return False
    card = build_card()
    data = json.dumps(card).encode()
    req  = urllib.request.Request(webhook, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        res = urllib.request.urlopen(req, timeout=15)
        return res.status in (200, 202)
    except urllib.error.HTTPError as e:
        print(f"Teams 失敗 HTTP {e.code}: {e.read().decode()[:200]}")
        return False


def send_email(to: str = EMAIL_TO, subject: str = None) -> bool:
    """將純文字日報寄到指定信箱，透過 10.11.1.125 relay。"""
    content = run(full=True)
    subject = subject or f"【每日晨報】{TODAY}"

    msg = MIMEMultipart()
    msg['From']    = EMAIL_FROM
    msg['To']      = to
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain', 'utf-8'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"郵件發送失敗：{e}")
        return False


if __name__ == "__main__":
    import sys
    if "--email" in sys.argv:
        idx = sys.argv.index("--email")
        to  = sys.argv[idx + 1] if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("--") else EMAIL_TO
        ok  = send_email(to=to)
        print(f"✅ 日報已寄至 {to}" if ok else "❌ 郵件發送失敗")
    elif "--teams" in sys.argv:
        url = None
        for i, a in enumerate(sys.argv):
            if a == "--teams" and i + 1 < len(sys.argv):
                url = sys.argv[i + 1]
        ok = send_to_teams(url)
        print("✅ 已發送到 Teams" if ok else "❌ Teams 發送失敗")
    elif "--file" in sys.argv:
        arg = sys.argv[sys.argv.index("--file") + 1] if sys.argv.index("--file") + 1 < len(sys.argv) else "."
        p   = Path(arg).expanduser()
        if p.suffix:          # 有副檔名 → 當完整路徑
            out = p
            out.parent.mkdir(parents=True, exist_ok=True)
        else:                 # 無副檔名 → 當目錄，自動加日期檔名
            p.mkdir(parents=True, exist_ok=True)
            out = p / f"{TODAY}.md"
        content = run(full=True)
        out.write_text(content)
        print(content)
        print(f"\n已存至 {out}")
    else:
        print(run())
