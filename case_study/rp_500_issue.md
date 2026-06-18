# Case Study: recruitment.ubiqconn.com — RP Port 8000 Causing External 500 Errors

## Summary

`recruitment.ubiqconn.com` experienced external-facing HTTP 500 errors due to a Reverse Proxy (RP) incorrectly bound to port 8000. Incoming requests never reached the Kubernetes Ingress layer, meaning the service appeared healthy internally while failing for all external users.

---

## Timeline

| Time | Event |
|------|-------|
| T+0  | External users report HTTP 500 on `recruitment.ubiqconn.com` |
| T+10 | Internal health checks pass — K8s pods and services confirmed running |
| T+25 | `curl -I https://recruitment.ubiqconn.com` returns `500 Internal Server Error` |
| T+30 | Traffic analysis reveals requests terminating at RP layer, not reaching Ingress |
| T+45 | Root cause identified: RP listener bound to port 8000 instead of port 443/80 |
| T+60 | RP reconfigured to forward on correct port; 500 errors resolved |

---

## Root Cause

The Reverse Proxy (RP) — likely nginx or HAProxy acting as the external entry point — was configured to listen on **port 8000** for incoming HTTPS traffic destined for `recruitment.ubiqconn.com`.

Because no external load balancer or firewall rule forwarded port 443 → 8000, requests on the standard HTTPS port arrived at the RP but had no matching listener. The RP responded with a generic 500 rather than a connection refusal, masking the misconfiguration.

```
[External Client]
      │ HTTPS :443
      ▼
[Reverse Proxy]  ← listener bound to :8000, NOT :443
      │ No matching vhost → 500
      ✗  (request never forwarded)
[K8s Ingress Controller]  ← never reached
      │
[Ingress Resource: recruitment.ubiqconn.com]
      │
[Service → Pod]
```

---

## Why K8s Ingress Was Not Reached

The Kubernetes Ingress Controller only receives traffic that the RP successfully proxies upstream. Since the RP dropped the request at the listener stage, the Ingress logs showed **zero entries** during the incident window — confirming the failure was pre-Ingress.

Ingress-level checks that appeared healthy:
- `kubectl get ingress -n recruitment` → STATUS: Active
- `kubectl describe ingress recruitment-ingress` → rules correctly defined
- Pod readiness probes → all passing

These all passed because the failure was entirely in the RP layer, outside the cluster.

---

## Diagnostic Steps That Identified the Issue

1. **External curl check**
   ```bash
   curl -I https://recruitment.ubiqconn.com
   # HTTP/1.1 500 Internal Server Error
   ```

2. **RP access log inspection** — found requests being received on `:443` with no matching server block.

3. **RP configuration audit**
   ```nginx
   server {
       listen 8000;   # BUG: should be 443 ssl
       server_name recruitment.ubiqconn.com;
       ...
   }
   ```

4. **Firewall / load balancer rule review** — confirmed no port-forwarding rule for 443 → 8000.

5. **K8s Ingress log confirmation** — zero request entries during incident, confirming traffic never entered the cluster.

---

## Fix Applied

Updated the RP server block to listen on the correct port:

```nginx
# Before (broken)
server {
    listen 8000;
    server_name recruitment.ubiqconn.com;
}

# After (fixed)
server {
    listen 443 ssl;
    server_name recruitment.ubiqconn.com;
    ssl_certificate     /etc/ssl/certs/ubiqconn.crt;
    ssl_certificate_key /etc/ssl/private/ubiqconn.key;

    location / {
        proxy_pass http://k8s-ingress-controller:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

After reloading the RP (`nginx -s reload`), traffic flowed correctly through to K8s Ingress and the 500 errors ceased.

---

## Prevention & Follow-up Actions

| Action | Owner | Priority |
|--------|-------|----------|
| Add automated external health check (curl -I) to monitoring pipeline | SRE | High |
| Add pre-deploy RP config lint (`nginx -t`) to CI/CD | DevOps | High |
| Document RP port standards in runbook | DevOps | Medium |
| Review all other RP vhosts for similar port mismatches | DevOps | Medium |
| Set up alert: Ingress request rate drops to zero for >2 min | SRE | High |

---

## Lessons Learned

- **Internal health checks are insufficient** — K8s-level readiness and liveness probes cannot detect failures that occur before traffic enters the cluster.
- **RP is a silent chokepoint** — a misconfigured RP listener returns 500 without surfacing the real cause in application logs.
- **External synthetic monitoring is mandatory** — a simple periodic `curl -I` from outside the cluster would have caught this within minutes.
- **Port standards must be enforced at review time** — a CI lint step (`nginx -t` + a port policy check) would have blocked this misconfiguration at deploy time.
