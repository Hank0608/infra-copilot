"""kubectl wrapper — runs commands against the prod cluster via kubeconfig."""

import subprocess
import os
import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent
KUBECONFIG = os.path.expanduser("~/.kube/prod-config")


def kubectl(args: list[str], timeout: int = 30) -> dict:
    """Run a kubectl command and return {stdout, stderr, exit_code}."""
    cmd = ["kubectl", "--kubeconfig", KUBECONFIG] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
    }


def get_pods(namespace: str = None, label: str = None) -> dict:
    args = ["get", "pods", "-o", "wide"]
    if namespace:
        args += ["-n", namespace]
    else:
        args += ["-A"]
    if label:
        args += ["-l", label]
    return kubectl(args)


def describe_pod(pod: str, namespace: str) -> dict:
    return kubectl(["describe", "pod", pod, "-n", namespace])


def pod_logs(pod: str, namespace: str, previous: bool = False, tail: int = 50) -> dict:
    args = ["logs", pod, "-n", namespace, f"--tail={tail}"]
    if previous:
        args.append("--previous")
    return kubectl(args)


def get_ingress(namespace: str = None) -> dict:
    args = ["get", "ingress", "-o", "wide"]
    args += ["-n", namespace] if namespace else ["-A"]
    return kubectl(args)


def check_service_health(keyword: str) -> dict:
    """
    Find pods matching a keyword across all namespaces and report health.
    Returns a summary dict with pod states.
    """
    result = get_pods()
    if result["exit_code"] != 0:
        return {"error": result["stderr"], "pods": []}

    pods = []
    for line in result["stdout"].splitlines()[1:]:
        if keyword.lower() in line.lower():
            parts = line.split()
            if len(parts) >= 4:
                pods.append({
                    "namespace": parts[0],
                    "name": parts[1],
                    "ready": parts[2],
                    "status": parts[3],
                    "restarts": parts[4] if len(parts) > 4 else "?",
                })

    healthy = all(p["status"] == "Running" and not p["ready"].startswith("0/") for p in pods)
    return {"healthy": healthy, "pods": pods, "raw": result["stdout"]}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: k8s_runner.py <kubectl args...>")
        sys.exit(1)
    r = kubectl(sys.argv[1:])
    print(r["stdout"])
    if r["stderr"]:
        print(r["stderr"], file=sys.stderr)
    sys.exit(r["exit_code"])
