#!/usr/bin/env python3
"""HTTP diagnostic tool — checks a URL with curl -I and advises on failures."""

import subprocess
import sys
import re


def check_url(url: str) -> None:
    print(f"[diag] Checking: {url}")

    try:
        result = subprocess.run(
            ["curl", "-I", "--max-time", "10", "--silent", "--show-error", url],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        print("[FAIL] Request timed out (subprocess timeout)")
        _advise_timeout(url)
        sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] curl not found — please install curl")
        sys.exit(2)

    output = result.stdout + result.stderr

    # Parse status code from first HTTP response line (handles HTTP/1.1 and HTTP/2)
    match = re.search(r"HTTP/[\d.]+ (\d{3})", output)

    if result.returncode != 0 and not match:
        # curl itself failed (e.g. DNS failure, connection refused, SSL error)
        print(f"[FAIL] curl error (exit {result.returncode}): {result.stderr.strip()}")
        _advise_timeout(url)
        sys.exit(1)

    if not match:
        print("[WARN] Could not parse HTTP status from response headers.")
        print("       Raw output:")
        print(output[:500])
        sys.exit(1)

    status = int(match.group(1))
    print(f"[diag] HTTP status: {status}")

    if status == 500:
        print("[FAIL] 500 Internal Server Error detected.")
        _advise_500(url)
        sys.exit(1)
    elif status >= 400:
        print(f"[WARN] Client/server error: {status}")
    else:
        print(f"[OK]  {url} is reachable (HTTP {status})")


def _advise_500(url: str) -> None:
    print()
    print("Troubleshooting checklist for HTTP 500:")
    print(f"  1. Verify Reverse Proxy listener port matches the external-facing port for {url}")
    print("     e.g. nginx 'listen' directive should be 443 (ssl) or 80, not 8000/8080")
    print("  2. Confirm firewall / load balancer forwards port 443 → RP, not directly to app port")
    print("  3. Check RP upstream block points to correct K8s Ingress Controller address")
    print("  4. Inspect RP error logs:  tail -f /var/log/nginx/error.log")
    print("  5. Verify K8s Ingress is receiving traffic:")
    print("     kubectl logs -n ingress-nginx deploy/ingress-nginx-controller | tail -50")
    print("  6. If Ingress logs are empty during the 500 window, failure is pre-Ingress (RP layer)")


def _advise_timeout(url: str) -> None:
    print()
    print("Troubleshooting checklist for timeout / connection failure:")
    print(f"  1. Confirm DNS resolves correctly:  dig {url.split('//')[-1].split('/')[0]}")
    print("  2. Check firewall rules allow inbound 443/80 to the RP host")
    print("  3. Verify RP process is running:  systemctl status nginx")
    print("  4. Confirm RP is bound to the expected interface (not 127.0.0.1 only)")
    print("  5. Test connectivity bypassing DNS:  curl -I --resolve host:443:<IP> <url>")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://recruitment.ubiqconn.com")
        sys.exit(1)

    check_url(sys.argv[1])
