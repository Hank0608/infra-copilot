"""Server-centric monitoring dashboard — Zabbix + Wazuh + AD + Backup aggregated view."""

import datetime
import threading
from pathlib import Path

import yaml
from flask import Flask, jsonify, render_template, redirect, url_for, request

from tools import ad_runner as ad
from tools import wazuh_runner as wz
from tools import zabbix_runner as zb
from tools import ppdm_runner as ppdm
from tools import synology_runner as syn
from tools import fortigate_runner as fw
from tools import dell_me_runner as me

app = Flask(__name__, template_folder="templates")
ROOT = Path(__file__).parent

_state: dict = {
    "servers":        [],
    "ad_global":      {},
    "ppdm":           None,
    "synology":       [],
    "dell_me":        {},
    "updated":        None,
    "loading":        False,
    "backup_loading":  False,
    "backup_updated":  None,
    "network":         {},
    "network_loading": False,
    "network_updated": None,
    "error":           None,
}
_lock = threading.Lock()


# ── status helper ─────────────────────────────────────────

def _bump(current: str, new: str) -> str:
    rank = {"ok": 0, "warn": 1, "error": 2}
    return new if rank.get(new, 0) > rank.get(current, 0) else current


# ── data collection ───────────────────────────────────────

def _load_focus() -> list:
    inv = yaml.safe_load((ROOT / "inventory.yaml").read_text())
    return inv.get("dashboard_servers", [])


def _collect(hours: int = 24):
    with _lock:
        if _state["loading"]:
            return
        _state["loading"] = True
        _state["error"]   = None

    try:
        servers = _load_focus()

        # ── AD LDAP ───────────────────────────────────
        try:
            locked = ad.get_locked_accounts()
        except Exception:
            locked = []

        try:
            expiring = ad.get_expiring_passwords(days=14)
        except Exception:
            expiring = []

        try:
            changes = ad.get_recent_account_changes(days=7)
        except Exception:
            changes = {"created": [], "disabled": []}

        # ── AD 事件 via Wazuh ─────────────────────────
        try:
            lockout_events = wz.get_dc_lockouts(hours=24)
        except Exception:
            lockout_events = []

        try:
            logon_summary = wz.get_dc_logon_failure_summary(hours=24)
        except Exception:
            logon_summary = {"total": 0, "by_user": [], "by_status": {}}

        # ── Zabbix ───────────────────────────────────
        zb_data: dict = {"by_name": {}, "by_ip": {}}
        try:
            token = zb.login()
            try:
                zb_data = zb.get_all_host_data(token)
            finally:
                zb.logout(token)
        except Exception:
            pass

        # ── Wazuh ────────────────────────────────────
        agent_names = [s["wazuh"] for s in servers if s.get("wazuh")]
        try:
            wz_issues = wz.get_agent_issues(agent_names, hours=hours)
        except Exception:
            wz_issues = {}

        # ── PPDM / Synology 由 _collect_backup() 獨立更新，此處略過 ──

        # ── per-server cards ──────────────────────────
        active_locked  = [l for l in locked if not l["disabled"]]
        overdue        = [u for u in expiring if u["daysLeft"] < 0]
        urgent         = [u for u in expiring if 0 <= u["daysLeft"] <= 3]
        high_fail      = [(u, c) for u, c in logon_summary.get("by_user", []) if c >= 20]

        results = []
        for srv in servers:
            status  = "ok"
            ad_card = None

            if srv.get("ad_dc"):
                ad_card = {
                    "locked":           active_locked,
                    "lockout_events":   lockout_events[:10],
                    "logon_total":      logon_summary.get("total", 0),
                    "high_fail":        high_fail[:5],
                    "expiring_overdue": overdue[:5],
                    "expiring_urgent":  urgent[:5],
                    "changes":          changes,
                }
                if active_locked:
                    status = _bump(status, "warn")
                if lockout_events:
                    status = _bump(status, "warn")
                if [l for l in active_locked if l["high_risk"]]:
                    status = _bump(status, "error")
                if overdue:
                    status = _bump(status, "warn")

            # ── Zabbix card ───────────────────────────
            zb_card = None
            zrec = None
            zname = srv.get("zabbix")
            if zname:
                zrec = zb_data["by_name"].get(zname.lower())
            if not zrec and srv.get("ip"):
                zrec = zb_data["by_ip"].get(srv["ip"])

            if zrec:
                zb_card = {
                    "name":     zrec["name"],
                    "status":   zrec["status"],
                    "error":    zrec["error"],
                    "problems": zrec["problems"],
                }
                if zrec["status"] == "down":
                    status = _bump(status, "error")
                elif zrec["problems"]:
                    max_sev = max(p["severity"] for p in zrec["problems"])
                    status  = _bump(status, "error" if max_sev >= 4 else "warn")

            # ── Wazuh card ────────────────────────────
            wz_card = None
            wname   = srv.get("wazuh")
            if wname:
                issues  = wz_issues.get(wname, [])
                wz_card = {"agent": wname, "issues": issues}
                if issues:
                    _ALWAYS_TRIGGER = {"19003", "19011", "19013", "19014", "23505"}
                    effective = [i for i in issues if i["level"] >= 10
                                 or i.get("count", 0) >= 10
                                 or i["rule_id"] in _ALWAYS_TRIGGER]
                    if effective:
                        max_level = max(i["level"] for i in effective)
                        status = _bump(status, "error" if max_level >= 12 else "warn")

            results.append({
                "label":  srv["label"],
                "ip":     srv.get("ip", ""),
                "team":   srv.get("team", ""),
                "desc":   srv.get("desc", ""),
                "status": status,
                "ad":     ad_card,
                "zabbix": zb_card,
                "wazuh":  wz_card,
            })

        order = {"error": 0, "warn": 1, "ok": 2}
        results.sort(key=lambda c: (order.get(c["status"], 9), c["team"], c["label"]))

        with _lock:
            _state["servers"]   = results
            _state["hours"]     = hours
            _state["ad_global"] = {
                "locked_total":   len(active_locked),
                "expiring_total": len(expiring),
                "overdue_total":  len(overdue),
            }
            _state["updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _state["loading"] = False

    except Exception as e:
        with _lock:
            _state["loading"] = False
            _state["error"]   = str(e)


def _collect_backup():
    """只收 PPDM + Synology，速度快，與主 dashboard 互不干擾。"""
    with _lock:
        if _state["backup_loading"]:
            return
        _state["backup_loading"] = True

    try:
        ppdm_card = None
        try:
            ppdm_card = ppdm.get_dashboard_card(hours=24)
        except Exception:
            pass

        syn_cards = []
        for nas in syn.get_nas_list():
            try:
                card = syn.get_nas_card(nas["host"], nas["label"])
            except Exception as e:
                card = {
                    "label": nas["label"], "host": nas["host"],
                    "status": "error", "errors": [str(e)],
                    "volumes": [], "disks": [], "info": {}, "abb_tasks": [],
                }
            syn_cards.append(card)

        # Dell ME replication
        dell_me_data = {}
        try:
            _TZ8 = datetime.timezone(datetime.timedelta(hours=8))
            _REP_OK = {1, 4}  # Synchronized, Ready
            all_me  = me.get_all_hosts(hours=24)
            sets    = me.dedup_sets(all_me)
            now     = datetime.datetime.now(tz=_TZ8)

            rep_sets = []
            for rs in sets:
                st_num  = rs["status_num"]
                run_num = rs["last_run_num"]
                ok      = st_num in _REP_OK and run_num == 1
                last_dt = rs["last_success"]
                hours_ago = int((now - last_dt).total_seconds() / 3600) if last_dt else None
                last_str  = last_dt.strftime("%m/%d %H:%M") if last_dt else "—"
                rep_sets.append({
                    "name":      rs["name"],
                    "peer":      rs["peer"],
                    "status":    "ok" if ok else "error",
                    "run_ok":    run_num == 1,
                    "active":    rs["active"],
                    "last":      last_str,
                    "hours_ago": hours_ago,
                })

            peers = []
            seen_peers = set()
            for host in me.ME_HOSTS:
                for p in all_me.get(host, {}).get("peers", []):
                    key = p["name"]
                    if key not in seen_peers:
                        seen_peers.add(key)
                        peers.append({
                            "name":   p["name"],
                            "status": p["status"],
                            "ok":     p["status_num"] == 1,
                        })

            overall = "error" if any(rs["status"] == "error" for rs in rep_sets) else "ok"
            dell_me_data = {"sets": rep_sets, "peers": peers, "overall": overall, "error": None}
        except Exception as e:
            dell_me_data = {"sets": [], "peers": [], "overall": "error", "error": str(e)}

        with _lock:
            _state["ppdm"]           = ppdm_card
            _state["synology"]       = syn_cards
            _state["dell_me"]        = dell_me_data
            _state["backup_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _state["backup_loading"] = False

    except Exception as e:
        with _lock:
            _state["backup_loading"] = False


def _collect_network():
    """收 FortiGate（未來含 Switch）資料，與主 dashboard 互不干擾。"""
    with _lock:
        if _state["network_loading"]:
            return
        _state["network_loading"] = True

    try:
        fortigate = {}
        try:
            fortigate = fw.get_report_data()
        except Exception as e:
            fortigate = {"error": str(e)}

        with _lock:
            _state["network"]         = {"fortigate": fortigate}
            _state["network_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _state["network_loading"] = False

    except Exception:
        with _lock:
            _state["network_loading"] = False


# ── routes ────────────────────────────────────────────────

@app.route("/")
def index():
    hours = int(request.args.get("hours", 24))
    if not _state["servers"] and not _state["loading"]:
        _collect(hours)
    elif _state.get("hours") != hours and not _state["loading"]:
        threading.Thread(target=_collect, args=(hours,), daemon=True).start()
    return render_template("dashboard.html", state=_state, hours=hours)


@app.route("/backup")
def backup():
    hours = int(request.args.get("hours", 24))
    if not _state["backup_updated"] and not _state["backup_loading"]:
        threading.Thread(target=_collect_backup, daemon=True).start()
    return render_template("backup.html",
        ppdm=_state.get("ppdm"),
        synology=_state.get("synology", []),
        dell_me=_state.get("dell_me", {}),
        updated=_state.get("backup_updated"),
        loading=_state.get("backup_loading"),
        hours=hours)


@app.route("/api/data")
def api_data():
    return jsonify(_state)


@app.route("/detail/ad")
def detail_ad():
    label = request.args.get("label", "")
    hours = int(request.args.get("hours", 24))

    data, error = {}, None
    try:
        data["locked"]   = ad.get_locked_accounts()
        data["expiring"] = ad.get_expiring_passwords(days=30)
        data["changes"]  = ad.get_recent_account_changes(days=7)
        data["lockout_events"]   = wz.get_dc_lockouts(hours=hours)
        data["logon_failures"]   = wz.get_dc_logon_failures(hours=hours, limit=200)
        data["logon_summary"]    = wz.get_dc_logon_failure_summary(hours=hours)
    except Exception as e:
        error = str(e)

    return render_template("detail_ad.html",
        label=label, hours=hours, data=data, error=error,
        sub_status=wz._SUB_STATUS)


@app.route("/detail/wazuh")
def detail_wazuh():
    agent   = request.args.get("agent", "")
    rule_id = request.args.get("rule", "")
    label   = request.args.get("label", agent)
    hours   = int(request.args.get("hours", 24))

    zh, action   = wz._RULE_MAP.get(rule_id, (f"rule {rule_id}", "確認告警詳情"))
    summary, steps = wz._RULE_DETAIL.get(rule_id, ("", []))

    analysis, error = {}, None
    try:
        analysis = wz.get_rule_analysis(agent, rule_id, hours=hours)
    except Exception as e:
        error = str(e)

    return render_template("detail_wazuh.html",
        label=label, agent=agent, rule_id=rule_id,
        zh=zh, action=action, summary=summary, steps=steps,
        analysis=analysis, hours=hours, error=error)


@app.route("/detail/ad/user")
def detail_ad_user():
    username = request.args.get("username", "")
    hours    = int(request.args.get("hours", 24))

    user_info, failures, lockouts = None, [], []
    error = None
    try:
        user_info = ad.get_user(username)
        failures  = wz.get_dc_logon_failures(username=username, hours=hours, limit=500)
        all_lo    = wz.get_dc_lockouts(hours=max(hours, 168))
        lockouts  = [e for e in all_lo if e["target_user"].upper() == username.upper()]
    except Exception as e:
        error = str(e)

    return render_template("detail_ad_user.html",
        username=username, hours=hours,
        user_info=user_info, failures=failures, lockouts=lockouts,
        error=error, sub_status=wz._SUB_STATUS)


@app.route("/detail/wazuh/agent")
def detail_wazuh_agent():
    agent = request.args.get("agent", "")
    label = request.args.get("label", agent)
    hours = int(request.args.get("hours", 24))

    data, error = {}, None
    try:
        data = wz.get_agent_overview(agent, hours=hours, min_level=8)
    except Exception as e:
        error = str(e)

    return render_template("detail_wazuh_agent.html",
        agent=agent, label=label, hours=hours, data=data, error=error)


@app.route("/detail/wazuh/event")
def detail_wazuh_event():
    agent    = request.args.get("agent", "")
    rule_id  = request.args.get("rule", "")
    event_id = request.args.get("event_id", "")
    label    = request.args.get("label", agent)
    hours    = int(request.args.get("hours", 24))

    zh, _       = wz._RULE_MAP.get(rule_id, (f"rule {rule_id}", ""))
    explain, ev_action = wz._WIN_EVENT_EXPLAIN.get(event_id, ("", ""))

    data, error = {}, None
    try:
        data = wz.get_eventid_events(agent, rule_id, event_id, hours=hours)
    except Exception as e:
        error = str(e)

    return render_template("detail_event.html",
        label=label, agent=agent, rule_id=rule_id, event_id=event_id,
        zh=zh, explain=explain, ev_action=ev_action,
        data=data, hours=hours, error=error)


@app.route("/detail/zabbix")
def detail_zabbix():
    host  = request.args.get("host", "")
    label = request.args.get("label", host)

    data, error = {}, None
    try:
        token = zb.login()
        try:
            data = zb.get_host_detail(host, token)
        finally:
            zb.logout(token)
    except Exception as e:
        error = str(e)

    return render_template("detail_zabbix.html",
        label=label, host=host, data=data, error=error)


@app.route("/detail/ppdm")
def detail_ppdm():
    label = request.args.get("label", "PPDM")
    hours = int(request.args.get("hours", 24))

    data, error = {}, None
    try:
        data = ppdm.get_detail(hours=hours)
    except Exception as e:
        error = str(e)

    return render_template("detail_ppdm.html",
        label=label, hours=hours, data=data, error=error)


@app.route("/detail/dell_me")
def detail_dell_me():
    hours = int(request.args.get("hours", 48))
    data, error = {}, None
    try:
        _TZ8 = datetime.timezone(datetime.timedelta(hours=8))
        _REP_OK  = {1, 4}
        all_data = me.get_all_hosts(hours=hours)
        sets     = me.dedup_sets(all_data)
        runs     = me.dedup_runs(all_data)
        now      = datetime.datetime.now(tz=_TZ8)

        rep_sets = []
        for rs in sets:
            ok       = rs["status_num"] in _REP_OK and rs["last_run_num"] == 1
            last_dt  = rs["last_success"]
            hours_ago = int((now - last_dt).total_seconds() / 3600) if last_dt else None
            rep_sets.append({
                "name":      rs["name"],
                "peer":      rs["peer"],
                "primary":   rs["primary_vol"],
                "status":    rs["status"],
                "run":       rs["last_run"],
                "ok":        ok,
                "active":    rs["active"],
                "queue":     rs["queue_count"],
                "last":      last_dt.strftime("%m/%d %H:%M") if last_dt else "—",
                "hours_ago": hours_ago,
            })

        run_rows = []
        for set_name, rlist in sorted(runs.items()):
            for r in rlist:
                h, m = divmod(r["dur_min"] or 0, 60)
                dur  = f"{h}h{m:02d}m" if h else (f"{m}m" if m else "—")
                run_rows.append({
                    "set":    set_name,
                    "state":  r["state"],
                    "start":  r["start"].strftime("%m/%d %H:%M") if r["start"] else "—",
                    "end":    r["end"].strftime("%H:%M") if r["end"] else "—",
                    "result": r["result"],
                    "dur":    dur,
                    "gb":     f"{r['data_gb']:.1f}" if r.get("data_gb") else "—",
                })

        peers = []
        seen  = set()
        for host in me.ME_HOSTS:
            for p in all_data.get(host, {}).get("peers", []):
                if p["name"] not in seen:
                    seen.add(p["name"])
                    peers.append({**p, "host": host})

        events = []
        for host in me.ME_HOSTS:
            for e in all_data.get(host, {}).get("events", []):
                events.append({**e, "ts": e["time"].strftime("%m/%d %H:%M") if e["time"] else "—"})
        events.sort(key=lambda x: x["time"] or datetime.datetime.min.replace(tzinfo=_TZ8), reverse=True)

        data = {"sets": rep_sets, "runs": run_rows, "peers": peers, "events": events[:30]}
    except Exception as e:
        error = str(e)

    return render_template("detail_dell_me.html", hours=hours, data=data, error=error)


@app.route("/network")
def network():
    if not _state["network_updated"] and not _state["network_loading"]:
        threading.Thread(target=_collect_network, daemon=True).start()
    return render_template("network.html",
        network=_state.get("network", {}),
        updated=_state.get("network_updated"),
        loading=_state.get("network_loading"))


@app.route("/refresh")
def refresh():
    threading.Thread(target=_collect, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/refresh/backup")
def refresh_backup():
    threading.Thread(target=_collect_backup, daemon=True).start()
    return redirect(url_for("backup"))


@app.route("/refresh/network")
def refresh_network():
    threading.Thread(target=_collect_network, daemon=True).start()
    return redirect(url_for("network"))


if __name__ == "__main__":
    threading.Thread(target=_collect, daemon=True).start()
    app.run(host="0.0.0.0", port=5050, debug=False)
