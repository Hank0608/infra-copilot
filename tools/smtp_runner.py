"""SMTP runner — 連線測試、mail log 讀取與寄件問題分析。"""

import os
import re
import smtplib
import socket
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

SMTP_HOST = os.getenv("SMTP_HOST", "10.11.1.125")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "infra.ro")
SMTP_PASS = _secret("SMTP_PASS")

_TZ8 = timezone(timedelta(hours=8))

# ── Log 路徑候選（Postfix 在不同 distro 位置不同）──────────────
_LOG_CANDIDATES = [
    "/var/log/mail.log",
    "/var/log/maillog",
    "/var/log/mail/mail.log",
]

# ── Postfix log 解析 regex ─────────────────────────────────────
_RE_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)

# ── 錯誤模式分類 ──────────────────────────────────────────────
_ERROR_PATTERNS = [
    ("auth_fail",      re.compile(r"SASL.*(fail|error|reject)|authentication.*fail|535", re.I)),
    ("relay_denied",   re.compile(r"Relay access denied|550 5\.7\.|554 5\.7\.", re.I)),
    ("conn_refused",   re.compile(r"Connection refused|connect to.*\(port \d+\).*refused", re.I)),
    ("conn_timeout",   re.compile(r"Connection timed out|connect to.*\(port \d+\).*timed? out", re.I)),
    ("tls_error",      re.compile(r"TLS.*error|certificate.*verif|SSL.*error", re.I)),
    ("bounced",        re.compile(r"status=bounced", re.I)),
    ("deferred",       re.compile(r"status=deferred", re.I)),
    ("rejected",       re.compile(r"status=reject|NOQUEUE: reject|550 |554 ", re.I)),
    ("host_not_found", re.compile(r"Host or domain name not found|Name or service not known", re.I)),
    ("queue_full",     re.compile(r"queue file size limit exceeded|too many open files", re.I)),
]

_CATEGORY_LABEL = {
    "auth_fail":      "認證失敗",
    "relay_denied":   "Relay 拒絕",
    "conn_refused":   "連線被拒（對外 MX）",
    "conn_timeout":   "連線逾時（對外 MX）",
    "tls_error":      "TLS/SSL 錯誤",
    "bounced":        "退信 (bounced)",
    "deferred":       "延遲佇列 (deferred)",
    "rejected":       "郵件被拒 (rejected)",
    "host_not_found": "DNS 解析失敗",
    "queue_full":     "佇列/資源限制",
}


# ── 1. SMTP 連線測試 ───────────────────────────────────────────

def test_connection(host: str = SMTP_HOST, port: int = SMTP_PORT,
                    user: str = SMTP_USER, password: str = SMTP_PASS) -> dict:
    """測試 SMTP 連線與 SASL 認證。回傳 {ok, stage, banner, detail}。"""
    result = {"ok": False, "stage": None, "banner": "", "detail": ""}
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            result["banner"] = s.ehlo()[1].decode(errors="replace")
            result["stage"] = "connect"

            code, _ = s.ehlo()
            if code != 250:
                result["detail"] = f"EHLO 失敗，回應碼 {code}"
                return result
            result["stage"] = "ehlo"

            if port == 587:
                s.starttls()
                s.ehlo()
                result["stage"] = "starttls"

            if port != 25 and user and password:
                s.login(user, password)
                result["stage"] = "auth"
                result["detail"] = f"連線成功，已通過 SASL 認證（{user}）"
            else:
                result["detail"] = f"連線成功（port {port} relay 模式，IP 白名單認證）"

            result["ok"] = True
    except smtplib.SMTPAuthenticationError as e:
        result["detail"] = f"SASL 認證失敗：{e.smtp_error.decode(errors='replace')}"
    except smtplib.SMTPConnectError as e:
        result["detail"] = f"無法連線：{e}"
    except smtplib.SMTPException as e:
        result["detail"] = f"SMTP 錯誤（{result['stage']}）：{e}"
    except (socket.timeout, OSError) as e:
        result["detail"] = f"網路錯誤（{result['stage']}）：{e}"
    return result


# ── 2. 透過 SSH 取得 mail log ──────────────────────────────────

def _ssh_fetch_log(lines: int = 1000) -> tuple[str, str]:
    """
    SSH 進 smtp-server，找到第一個存在的 log 路徑並 tail。
    回傳 (raw_log, log_path)；找不到時回傳 ("", "")。
    """
    from tools.ssh_runner import run as ssh_run

    # 找第一個存在的 log 路徑（for loop 確保只印一個）
    candidates = " ".join(_LOG_CANDIDATES)
    check_cmd = f'for p in {candidates}; do [ -f "$p" ] && {{ echo "$p"; break; }}; done'
    r = ssh_run("smtp-server", check_cmd, timeout=10)
    log_path = r["stdout"].strip()
    if not log_path:
        return "", ""

    tail_cmd = f"sudo tail -n {lines} {log_path} 2>/dev/null || tail -n {lines} {log_path}"
    r = ssh_run("smtp-server", tail_cmd, timeout=30)
    return r["stdout"], log_path


# ── 3. Log 解析 ───────────────────────────────────────────────

def parse_log(raw: str) -> list[dict]:
    """
    把 mail log 原文解析成結構化紀錄，並標記 category。
    回傳 list of {ts_str, host, proc, msg, category}。
    """
    records = []
    year = datetime.now().year
    for line in raw.splitlines():
        m = _RE_LINE.match(line)
        if not m:
            continue
        msg = m.group("msg")
        cat = None
        for name, pat in _ERROR_PATTERNS:
            if pat.search(msg):
                cat = name
                break
        records.append({
            "ts_str":   f"{m.group('month')} {m.group('day')} {m.group('time')}",
            "host":     m.group("host"),
            "proc":     m.group("proc"),
            "msg":      msg,
            "category": cat,
        })
    return records


# ── 4. 問題分析 ───────────────────────────────────────────────

def analyze_issues(records: list[dict]) -> dict:
    """
    彙整錯誤統計、提取代表性錯誤訊息、推算影響收件人。
    回傳 {total, error_total, by_category, samples, affected_recipients}.
    """
    by_cat: dict[str, list] = defaultdict(list)
    recipients: set[str] = set()

    for r in records:
        if r["category"]:
            by_cat[r["category"]].append(r)
        # 嘗試從 msg 提取收件人
        m = re.search(r"to=<([^>]+)>", r["msg"])
        if m and r["category"] in ("bounced", "deferred", "rejected", "relay_denied"):
            recipients.add(m.group(1))

    summary = {
        "total":               len(records),
        "error_total":         sum(len(v) for v in by_cat.values()),
        "by_category":         {},
        "samples":             {},
        "affected_recipients": sorted(recipients),
    }
    for cat, rows in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        summary["by_category"][cat] = {
            "label": _CATEGORY_LABEL.get(cat, cat),
            "count": len(rows),
        }
        # 最多 3 筆代表性訊息（去重）
        seen, samples = set(), []
        for row in rows:
            key = row["msg"][:120]
            if key not in seen:
                seen.add(key)
                samples.append(f"[{row['ts_str']}] {row['msg']}")
            if len(samples) == 3:
                break
        summary["samples"][cat] = samples

    return summary


# ── 5. 格式化報告 ─────────────────────────────────────────────

def _fmt_report(log_path: str, analysis: dict) -> str:
    lines = [
        "=" * 60,
        "  SMTP 寄件問題分析報告",
        "=" * 60,
        f"Log 來源  : {log_path}",
        f"解析行數  : {analysis['total']}",
        f"錯誤總計  : {analysis['error_total']}",
    ]

    if not analysis["by_category"]:
        lines += ["", "  ✅ 未發現異常記錄"]
    else:
        lines.append("")
        lines.append("【錯誤分類】")
        for cat, info in analysis["by_category"].items():
            lines.append(f"  {'🔴' if info['count'] >= 10 else '🟡'} {info['label']:18s} × {info['count']}")

        lines.append("")
        lines.append("【代表性錯誤（每類最多 3 筆）】")
        for cat, samples in analysis["samples"].items():
            label = _CATEGORY_LABEL.get(cat, cat)
            lines.append(f"\n▶ {label}")
            for s in samples:
                lines.append(f"  {s[:120]}")

    if analysis["affected_recipients"]:
        lines.append("")
        lines.append("【受影響收件人】")
        for addr in analysis["affected_recipients"][:20]:
            lines.append(f"  • {addr}")
        if len(analysis["affected_recipients"]) > 20:
            lines.append(f"  ... 共 {len(analysis['affected_recipients'])} 筆")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ── 6. 一鍵診斷入口 ───────────────────────────────────────────

def diagnose(log_lines: int = 2000, raw_log: str = None) -> str:
    """
    完整診斷：連線測試 → 取 log → 解析 → 輸出報告。
    raw_log: 若已有 log 原文可直接傳入，跳過 SSH 步驟（用於測試）。
    """
    report_parts = []

    # 連線測試
    conn = test_connection()
    status = "✅ 正常" if conn["ok"] else f"❌ 失敗（卡在 {conn['stage']}）"
    report_parts.append(
        f"【SMTP 連線】{SMTP_HOST}:{SMTP_PORT}\n"
        f"  狀態：{status}\n"
        f"  {conn['detail']}"
    )
    if conn["banner"]:
        banner_first = conn["banner"].splitlines()[0]
        report_parts[-1] += f"\n  Banner：{banner_first}"

    # 取 log
    if raw_log is None:
        raw_log, log_path = _ssh_fetch_log(log_lines)
        if not raw_log:
            report_parts.append("【Mail Log】⚠️  無法取得 log（路徑不存在或權限不足）")
            return "\n\n".join(report_parts)
    else:
        log_path = "(傳入原文)"

    # 解析 + 報告
    records  = parse_log(raw_log)
    analysis = analyze_issues(records)
    report_parts.append(_fmt_report(log_path, analysis))

    return "\n\n".join(report_parts)


# ── 7. 單純取 log（供外部工具呼叫）──────────────────────────────

def fetch_raw_log(lines: int = 2000) -> tuple[str, str]:
    """回傳 (raw_log, log_path)，可直接傳給 parse_log() / analyze_issues()。"""
    return _ssh_fetch_log(lines)


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "diagnose"

    if cmd == "diagnose":
        lines = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
        print(diagnose(log_lines=lines))

    elif cmd == "test":
        conn = test_connection()
        print(f"{'✅' if conn['ok'] else '❌'} {conn['detail']}")
        if conn["banner"]:
            print(f"Banner: {conn['banner'].splitlines()[0]}")

    elif cmd == "log":
        lines = int(sys.argv[2]) if len(sys.argv) > 2 else 500
        raw, path = fetch_raw_log(lines)
        if raw:
            print(f"# {path}\n{raw}")
        else:
            print("無法取得 log")

    else:
        print("Usage: smtp_runner.py [diagnose [lines] | test | log [lines]]")
        sys.exit(1)
