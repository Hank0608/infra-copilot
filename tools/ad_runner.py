"""Active Directory LDAP client — 組織架構、帳號狀態、密碼到期查詢。"""

import os
import re
import ssl
import datetime
from contextlib import contextmanager
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

AD_SERVER = os.getenv("AD_SERVER", "10.11.1.121")
AD_DOMAIN = os.getenv("AD_DOMAIN", "uti.com")
AD_USER   = os.getenv("SMTP_USER", os.getenv("AD_USER", ""))
AD_PASS   = _secret("SMTP_PASS") or _secret("AD_PASS")
AD_PORT   = int(os.getenv("AD_PORT", "636"))         # 636 = LDAPS
AD_USE_SSL = os.getenv("AD_USE_SSL", "true").lower() != "false"
BASE_DN   = "DC=" + ",DC=".join(AD_DOMAIN.upper().split("."))

# userAccountControl 常用旗標
_UAC_DISABLED          = 0x0002
_UAC_DONT_EXPIRE_PASS  = 0x10000
_UAC_LOCKED            = 0x0010

# domain 密碼最長效期（天）；從 AD 讀取後快取
_MAX_PWD_DAYS: int = 90


def _connect():
    from ldap3 import Server, Connection, NTLM, Tls
    # DC 自簽憑證常見 → 不驗證 chain，只確保傳輸加密
    tls = Tls(validate=ssl.CERT_NONE) if AD_USE_SSL else None
    srv = Server(AD_SERVER, port=AD_PORT, use_ssl=AD_USE_SSL, tls=tls, connect_timeout=5)
    conn = Connection(srv,
                      user=f"{AD_DOMAIN}\\{AD_USER}",
                      password=AD_PASS,
                      authentication=NTLM,
                      auto_bind=True)
    return conn


@contextmanager
def _connection():
    """建立 LDAP 連線，離開 with 區塊時自動 unbind（含例外狀況）。"""
    conn = _connect()
    try:
        yield conn
    finally:
        conn.unbind()


def _cn(dn: str) -> str:
    """從 DN 字串取出 CN 值。"""
    if not dn:
        return ""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


_WIN_EPOCH_ZERO = datetime.datetime(1601, 1, 1)

def _pwd_expiry(pwd_last_set, uac: int) -> str:
    """回傳密碼到期日字串，或 None（永不到期）。"""
    if uac & _UAC_DONT_EXPIRE_PASS:
        return None
    if not pwd_last_set or pwd_last_set <= _WIN_EPOCH_ZERO + datetime.timedelta(days=1):
        return None  # 從未設定過密碼，視同永不到期（service account 初始狀態）
    expiry = pwd_last_set + datetime.timedelta(days=_MAX_PWD_DAYS)
    return expiry.strftime("%Y-%m-%d")


def _days_until(date_str):
    """回傳距到期剩幾天，None 表示永不到期。"""
    if date_str is None or date_str == "從未設定":
        return None
    d = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
    return (d - datetime.date.today()).days


def _fetch_max_pwd_days(conn) -> int:
    global _MAX_PWD_DAYS
    from ldap3 import SUBTREE
    conn.search(BASE_DN, "(objectClass=domain)", attributes=["maxPwdAge"])
    if conn.entries:
        raw = conn.entries[0].maxPwdAge.value
        if hasattr(raw, "days"):
            _MAX_PWD_DAYS = abs(raw.days)
    return _MAX_PWD_DAYS


# ── 查詢函式 ──────────────────────────────────────────────

def get_user(username: str) -> dict:
    """查詢單一使用者詳細資訊。"""
    from ldap3 import SUBTREE
    with _connection() as conn:
        _fetch_max_pwd_days(conn)
        conn.search(
            BASE_DN,
            f"(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName", "displayName", "department", "title",
                "manager", "mail", "telephoneNumber",
                "pwdLastSet", "userAccountControl", "memberOf", "whenCreated",
            ],
        )
        if not conn.entries:
            return None
        e = conn.entries[0]
        uac = int(e.userAccountControl.value or 0)
        expiry = _pwd_expiry(
            e.pwdLastSet.value.replace(tzinfo=None) if e.pwdLastSet.value else None,
            uac,
        )
        return {
            "username":    str(e.sAMAccountName),
            "displayName": str(e.displayName),
            "department":  str(e.department),
            "title":       str(e.title),
            "manager":     _cn(str(e.manager)),
            "mail":        str(e.mail),
            "phone":       str(e.telephoneNumber),
            "groups":      [_cn(str(m)) for m in e.memberOf.values],
            "pwdExpiry":   expiry,
            "daysLeft":    _days_until(expiry),
            "disabled":    bool(uac & _UAC_DISABLED),
            "locked":      bool(uac & _UAC_LOCKED),
            "noExpire":    bool(uac & _UAC_DONT_EXPIRE_PASS),
            "created":     str(e.whenCreated.value)[:10] if e.whenCreated.value else "",
        }


def search_users(keyword: str, max_results: int = 20) -> list:
    """依姓名或部門關鍵字搜尋使用者（回傳摘要）。"""
    from ldap3 import SUBTREE
    with _connection() as conn:
        _fetch_max_pwd_days(conn)
        filt = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(|(displayName=*{keyword}*)(department=*{keyword}*)(sAMAccountName=*{keyword}*)))"
        )
        conn.search(
            BASE_DN, filt, search_scope=SUBTREE,
            attributes=["sAMAccountName", "displayName", "department", "title", "userAccountControl"],
            size_limit=max_results,
        )
        results = []
        for e in conn.entries:
            uac = int(e.userAccountControl.value or 0)
            results.append({
                "username":    str(e.sAMAccountName),
                "displayName": str(e.displayName),
                "department":  str(e.department),
                "title":       str(e.title),
                "disabled":    bool(uac & _UAC_DISABLED),
            })
        return results


def get_expiring_passwords(days: int = 14) -> list:
    """找出密碼將在 N 天內到期（或已到期）的帳號。"""
    from ldap3 import SUBTREE
    with _connection() as conn:
        _fetch_max_pwd_days(conn)
        conn.search(
            BASE_DN,
            # 排除停用帳號、電腦帳號（name 含 $）
            "(&(objectClass=user)(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(sAMAccountName=*$)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "displayName", "department", "pwdLastSet", "userAccountControl"],
            size_limit=500,
        )
        expiring = []
        for e in conn.entries:
            uac = int(e.userAccountControl.value or 0)
            if uac & _UAC_DONT_EXPIRE_PASS:
                continue
            pwd_set = e.pwdLastSet.value
            if pwd_set:
                pwd_set = pwd_set.replace(tzinfo=None)
            expiry = _pwd_expiry(pwd_set, uac)
            left   = _days_until(expiry)
            if left is not None and left <= days:
                expiring.append({
                    "username":    str(e.sAMAccountName),
                    "displayName": str(e.displayName),
                    "department":  str(e.department),
                    "pwdExpiry":   expiry,
                    "daysLeft":    left,
                })
        expiring.sort(key=lambda x: x["daysLeft"])
        return expiring


def get_group_members(group_name: str) -> list:
    """列出群組成員（僅直接成員，不含巢狀）。"""
    from ldap3 import SUBTREE
    with _connection() as conn:
        # 先找群組 DN
        conn.search(
            BASE_DN,
            f"(&(objectClass=group)(cn={group_name}))",
            attributes=["member"],
        )
        if not conn.entries:
            return []
        member_dns = conn.entries[0].member.values

        members = []
        for dn in member_dns:
            conn.search(
                str(dn), "(objectClass=user)",
                attributes=["sAMAccountName", "displayName", "department", "title"],
            )
            if conn.entries:
                e = conn.entries[0]
                members.append({
                    "username":    str(e.sAMAccountName),
                    "displayName": str(e.displayName),
                    "department":  str(e.department),
                    "title":       str(e.title),
                })
        return members


def get_department_users(department: str) -> list:
    """列出某部門所有啟用帳號。"""
    from ldap3 import SUBTREE
    with _connection() as conn:
        _fetch_max_pwd_days(conn)
        conn.search(
            BASE_DN,
            f"(&(objectClass=user)(objectCategory=person)(department=*{department}*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "displayName", "department", "title",
                        "manager", "mail", "pwdLastSet", "userAccountControl"],
        )
        results = []
        for e in conn.entries:
            uac = int(e.userAccountControl.value or 0)
            pwd_set = e.pwdLastSet.value
            if pwd_set:
                pwd_set = pwd_set.replace(tzinfo=None)
            expiry = _pwd_expiry(pwd_set, uac)
            results.append({
                "username":    str(e.sAMAccountName),
                "displayName": str(e.displayName),
                "department":  str(e.department),
                "title":       str(e.title),
                "manager":     _cn(str(e.manager)),
                "mail":        str(e.mail),
                "pwdExpiry":   expiry,
                "daysLeft":    _days_until(expiry),
                "disabled":    bool(uac & _UAC_DISABLED),
            })
        results.sort(key=lambda x: x["disabled"])
        return results


# ── Alert 類查詢 ───────────────────────────────────────────

def get_locked_accounts() -> list:
    """
    回傳所有鎖定帳號（lockoutTime > 0）。
    每筆: {username, displayName, department, disabled,
           locked_at, days_locked, bad_pwd_count, high_risk}
    high_risk: disabled=False 且 badPwdCount >= 5
    """
    with _connection() as conn:
        conn.search(
            BASE_DN,
            "(&(objectClass=user)(!(objectClass=computer))(lockoutTime>=1))",
            attributes=["sAMAccountName", "displayName", "department",
                        "lockoutTime", "badPwdCount", "userAccountControl"],
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        results = []
        for e in conn.entries:
            uac      = int(e.userAccountControl.value or 0)
            disabled = bool(uac & _UAC_DISABLED)
            lt       = e.lockoutTime.value
            bad_cnt  = int(e.badPwdCount.value or 0)
            days_locked = (now - lt).days if lt else 0
            results.append({
                "username":    e.sAMAccountName.value,
                "displayName": e.displayName.value or e.sAMAccountName.value,
                "department":  (e.department.value or "")[:30],
                "disabled":    disabled,
                "locked_at":   lt.strftime("%Y-%m-%d %H:%M") if lt else "",
                "days_locked": days_locked,
                "bad_pwd_count": bad_cnt,
                "high_risk":   not disabled and bad_cnt >= 5,
            })
        results.sort(key=lambda x: (-x["high_risk"], x["disabled"], -x["bad_pwd_count"]))
        return results


def get_stale_accounts(days: int = 90) -> list:
    """
    回傳啟用中但超過 days 天未登入的帳號。
    每筆: {username, displayName, department, last_logon, days_inactive}
    """
    with _connection() as conn:
        conn.search(
            BASE_DN,
            "(&(objectClass=user)(!(objectClass=computer))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(lastLogonTimestamp>=0))",
            attributes=["sAMAccountName", "displayName", "department", "lastLogonTimestamp"],
        )
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        results = []
        for e in conn.entries:
            lt = e.lastLogonTimestamp.value
            if not lt or lt >= cutoff:
                continue
            results.append({
                "username":      e.sAMAccountName.value,
                "displayName":   e.displayName.value or e.sAMAccountName.value,
                "department":    (e.department.value or "")[:30],
                "last_logon":    lt.strftime("%Y-%m-%d"),
                "days_inactive": (datetime.datetime.now(datetime.timezone.utc) - lt).days,
            })
        results.sort(key=lambda x: -x["days_inactive"])
        return results


def get_recent_account_changes(days: int = 7) -> dict:
    """
    回傳近 days 天內新建 / 停用的帳號。
    {created: [...], disabled: [...]}
    每筆: {username, displayName, department, changed_at}
    """
    since = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(days=days)).strftime("%Y%m%d%H%M%S.0Z")

    with _connection() as conn:
        def _search(filt, attrs):
            conn.search(BASE_DN, filt, attributes=attrs)
            return list(conn.entries)

        created_entries = _search(
            f"(&(objectClass=user)(!(objectClass=computer))(whenCreated>={since}))",
            ["sAMAccountName", "displayName", "department", "whenCreated"],
        )
        disabled_entries = _search(
            f"(&(objectClass=user)(!(objectClass=computer))"
            f"(userAccountControl:1.2.840.113556.1.4.803:=2)(whenChanged>={since}))",
            ["sAMAccountName", "displayName", "department", "whenChanged"],
        )

    def _fmt(entries, ts_attr):
        out = []
        for e in entries:
            ts = getattr(e, ts_attr).value
            out.append({
                "username":    e.sAMAccountName.value,
                "displayName": e.displayName.value or e.sAMAccountName.value,
                "department":  (e.department.value or "")[:30],
                "changed_at":  ts.strftime("%Y-%m-%d %H:%M") if ts else "",
            })
        return sorted(out, key=lambda x: x["changed_at"], reverse=True)

    return {
        "created":  _fmt(created_entries,  "whenCreated"),
        "disabled": _fmt(disabled_entries, "whenChanged"),
    }


def get_never_expire_accounts() -> list:
    """
    回傳啟用中且密碼永不到期的帳號（排除 Administrator / MSOL / AAD 系統帳號）。
    每筆: {username, displayName, department, pwd_last_set}
    """
    _SKIP = re.compile(r"^(Administrator|MSOL_|krbtgt|aadsync|Guest)", re.I)
    with _connection() as conn:
        conn.search(
            BASE_DN,
            "(&(objectClass=user)(!(objectClass=computer))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
            attributes=["sAMAccountName", "displayName", "department", "pwdLastSet"],
        )
        results = []
        for e in conn.entries:
            username = e.sAMAccountName.value or ""
            if _SKIP.match(username):
                continue
            pls = e.pwdLastSet.value
            results.append({
                "username":     username,
                "displayName":  e.displayName.value or username,
                "department":   (e.department.value or "")[:30],
                "pwd_last_set": pls.strftime("%Y-%m-%d") if pls else "未設定",
            })
        results.sort(key=lambda x: x["username"])
        return results


# ── 報告 ──────────────────────────────────────────────────

def password_expiry_report(warn_days: int = 14) -> str:
    """密碼到期預警報告。"""
    expiring = get_expiring_passwords(warn_days)

    lines = ["=" * 55, "  AD 密碼到期預警報告", "=" * 55]
    lines.append(f"\n警戒天數：{warn_days} 天內到期（含已到期）")
    lines.append(f"共 {len(expiring)} 筆\n")

    if not expiring:
        lines.append("  🎉 目前無帳號即將到期")
    else:
        overdue   = [u for u in expiring if u["daysLeft"] < 0]
        soon      = [u for u in expiring if 0 <= u["daysLeft"] <= warn_days]

        if overdue:
            lines.append(f"【已到期】{len(overdue)} 筆")
            for u in overdue:
                lines.append(f"  🔴 {u['displayName']:<20} ({u['username']:<15}) "
                              f"{u['department']}  到期：{u['pwdExpiry']}（{abs(u['daysLeft'])} 天前）")

        if soon:
            lines.append(f"\n【即將到期】{len(soon)} 筆")
            for u in soon:
                icon = "🟡" if u["daysLeft"] > 7 else "🟠"
                lines.append(f"  {icon} {u['displayName']:<20} ({u['username']:<15}) "
                              f"{u['department']}  剩 {u['daysLeft']} 天（{u['pwdExpiry']}）")

    lines.append("\n" + "=" * 55)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "expiry":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 14
            print(password_expiry_report(days))
        elif cmd == "user":
            u = get_user(sys.argv[2])
            if u:
                import json
                print(json.dumps(u, ensure_ascii=False, indent=2))
            else:
                print("找不到使用者")
        elif cmd == "search":
            results = search_users(sys.argv[2])
            for r in results:
                flag = "❌" if r["disabled"] else "✅"
                print(f"{flag} {r['displayName']:<20} ({r['username']:<15}) {r['department']} / {r['title']}")
        elif cmd == "dept":
            results = get_department_users(sys.argv[2])
            for r in results:
                flag = "❌" if r["disabled"] else "✅"
                print(f"{flag} {r['displayName']:<20} ({r['username']:<15}) {r['title']}  密碼：{r['pwdExpiry'] or '永不到期'}")
        elif cmd == "locked":
            for r in get_locked_accounts():
                risk = "🔴" if r["high_risk"] else ("⚪" if r["disabled"] else "🟠")
                print(f"{risk} {r['username']:<20} locked={r['locked_at']} ({r['days_locked']}d)  badPwd={r['bad_pwd_count']}  disabled={r['disabled']}")
        elif cmd == "stale":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 90
            for r in get_stale_accounts(days):
                print(f"⬜ {r['username']:<20} last={r['last_logon']} ({r['days_inactive']}d)  {r['department']}")
        elif cmd == "changes":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
            chg  = get_recent_account_changes(days)
            print(f"【新建 {len(chg['created'])} 筆】")
            for r in chg["created"]:
                print(f"  ✨ {r['username']:<20} {r['changed_at']}  {r['department']}")
            print(f"【停用 {len(chg['disabled'])} 筆】")
            for r in chg["disabled"]:
                print(f"  🚫 {r['username']:<20} {r['changed_at']}  {r['department']}")
        elif cmd == "never-expire":
            for r in get_never_expire_accounts():
                print(f"⚠️  {r['username']:<20} {r['department']:<30} pwd_last_set={r['pwd_last_set']}")
    else:
        print(password_expiry_report())
