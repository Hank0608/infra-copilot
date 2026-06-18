"""SSH runner — inventory-based + 直接 IP，支援 .env service account 或 AD Session。"""

import os
import sys
import yaml
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret


def _load_inventory() -> dict:
    with open(ROOT / "inventory.yaml") as f:
        return yaml.safe_load(f)


def _get_node(label: str) -> dict:
    inv = _load_inventory()
    node = inv["nodes"].get(label)
    if not node:
        raise ValueError(f"Node '{label}' not found in inventory.yaml")
    return node


def _ssh_connect(host: str, user: str, password: str, timeout: int):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # 只用提供的帳密；不 fallback 到本機 ssh-agent / ~/.ssh/id_*
    # 避免「AD 密碼錯時改用工程師個人金鑰登入」造成 audit log 身分不正確
    client.connect(
        hostname=host,
        username=user,
        password=password or None,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run(node_label: str, command: str, session=None, timeout: int = 30) -> dict:
    """
    SSH into a named inventory node and run a command.

    session: tools.auth.Session（AD 使用者），None 時退回 .env service account。
    Returns {"stdout": str, "stderr": str, "exit_code": int}.
    """
    try:
        import paramiko
    except ImportError:
        return {"stdout": "", "stderr": "paramiko not installed", "exit_code": 127}

    node = _get_node(node_label)
    host = node["ip"]
    ssh_auth = node.get("ssh_auth", "env")   # "env" | "ad"

    # ── 取得帳密 ──────────────────────────────────────────
    if ssh_auth == "ad":
        if session is None or not session.is_valid:
            return {
                "stdout": "",
                "stderr": f"Node '{node_label}' 需要 AD Session，請先呼叫 auth.login()",
                "exit_code": 1,
            }
        user     = session.ssh_user
        password = session.ssh_password
    else:
        user_env = node.get("ssh_user_env")
        pass_env = node.get("ssh_pass_env")
        if not user_env:
            return {
                "stdout": "",
                "stderr": f"Node '{node_label}' 未設定 ssh_user_env",
                "exit_code": 1,
            }
        user     = os.getenv(user_env, "")
        password = _secret(pass_env) if pass_env else ""
        if not user:
            return {"stdout": "", "stderr": f"Env var {user_env} 未設定", "exit_code": 1}

    # ── 執行 ──────────────────────────────────────────────
    client = None
    try:
        client = _ssh_connect(host, user, password, timeout)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        result = {
            "stdout": stdout.read().decode(errors="replace"),
            "stderr": stderr.read().decode(errors="replace"),
            "exit_code": exit_code,
        }
    except Exception as exc:
        err = str(exc)
        if "Authentication failed" in err:
            err = f"SSH 認證失敗（{user} → {host}）：帳密錯誤或無權限"
        result = {"stdout": "", "stderr": err, "exit_code": 1}
    finally:
        if client:
            client.close()

    return result


def run_on_ip(ip: str, command: str, session, timeout: int = 30) -> dict:
    """
    直接用 IP 連線（不查 inventory），搭配 AD Session 使用。
    供 linux_diag 等需要動態 IP 的場景。
    """
    try:
        import paramiko
    except ImportError:
        return {"stdout": "", "stderr": "paramiko not installed", "exit_code": 127}

    if session is None or not session.is_valid:
        return {"stdout": "", "stderr": "需要有效的 AD Session", "exit_code": 1}

    client = None
    try:
        client = _ssh_connect(ip, session.ssh_user, session.ssh_password, timeout)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        result = {
            "stdout": stdout.read().decode(errors="replace"),
            "stderr": stderr.read().decode(errors="replace"),
            "exit_code": exit_code,
        }
    except Exception as exc:
        err = str(exc)
        if "Authentication failed" in err:
            err = f"SSH 認證失敗（{session.ssh_user} → {ip}）：帳密錯誤或此主機未開放 AD 登入"
        result = {"stdout": "", "stderr": err, "exit_code": 1}
    finally:
        if client:
            client.close()

    return result


def print_result(label: str, command: str, result: dict) -> None:
    print(f"\n{'='*60}")
    print(f"[{label}] $ {command}")
    print(f"{'='*60}")
    if result["stdout"]:
        print(result["stdout"].rstrip())
    if result["stderr"]:
        print(f"[stderr] {result['stderr'].rstrip()}")
    print(f"[exit {result['exit_code']}]")


# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------

def check_nginx_port_conflict(node_label: str, domain: str = None) -> dict:
    """
    Fetch nginx config from node and look for non-standard listen ports.
    Returns a findings dict with any suspicious listen directives.
    """
    cmd = "grep -rn 'listen' /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null || true"
    result = run(node_label, cmd)

    findings = []
    suspicious_ports = []

    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Flag listen directives that are not 80, 443, or IPv6 variants
        import re
        m = re.search(r"listen\s+(\d+)", line)
        if m:
            port = int(m.group(1))
            if port not in (80, 443):
                suspicious_ports.append({"port": port, "line": line})
                findings.append(f"SUSPICIOUS: {line}")

    return {
        "raw_output": result["stdout"],
        "suspicious_ports": suspicious_ports,
        "findings": findings,
        "ssh_error": result["stderr"] if result["exit_code"] != 0 else None,
    }


def compare_states(label: str, command: str, expected_pattern: str) -> dict:
    """
    Run a command and check whether its output matches an expected pattern.
    Returns {"matched": bool, "output": str, "pattern": str}.
    """
    import re
    result = run(label, command)
    matched = bool(re.search(expected_pattern, result["stdout"]))
    return {
        "matched": matched,
        "output": result["stdout"],
        "pattern": expected_pattern,
        "ssh_error": result["stderr"] if result["exit_code"] != 0 else None,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run a command on an inventory node via SSH")
    parser.add_argument("node", help="Node label from inventory.yaml (e.g. rp-main)")
    parser.add_argument("command", help="Shell command to run on the remote host")
    args = parser.parse_args()

    r = run(args.node, args.command)
    print_result(args.node, args.command, r)
    sys.exit(r["exit_code"])
