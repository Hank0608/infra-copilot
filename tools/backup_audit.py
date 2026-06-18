"""跨備份方案保護狀態檢查 — PPDM + Synology ABB + Dell ME LUN replication。

對指定的 IP / hostname / VM-name，回傳在各備份系統中的保護狀態，
找出「沒備份」/「只 LUN 副本」/「真的 PPDM 在備」的差異。
"""

import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from tools import ppdm_runner as ppdm
from tools import synology_runner as syno
from tools.vsphere_runner import _connect, _disconnect, _find_vm, _POWER


# ME 上的 datastore → replication set name（基於現場觀察的命名約定）
# 注意：LUN replication ≠ backup，只是 storage HA，無 point-in-time 還原能力。
ME_DATASTORE_TO_REPSET = {
    "DellEMC ME4024": "REP_4024_TO_5224-1",
    "DellEMC ME5024": "REP_5024_TO_5224-2",
}


def _ppdm_robust_login(timeout: int = 60, retries: int = 2) -> str:
    """PPDM login with retry — bypass ppdm.login 的 hardcoded timeout=10。"""
    data = json.dumps({"username": ppdm.PPDM_USER, "password": ppdm.PPDM_PASS}).encode()
    url  = f"https://{ppdm.PPDM_HOST}:{ppdm.PPDM_PORT}/api/v2/login"
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data,
                                         headers={"Content-Type": "application/json"})
            res = urllib.request.urlopen(req, context=ppdm._CTX, timeout=timeout)
            return json.loads(res.read())["access_token"]
        except (TimeoutError, OSError) as e:
            if attempt < retries:
                time.sleep(1.5 ** attempt)
                continue
            raise RuntimeError(f"PPDM login failed: {e}")


def _ppdm_lookup(token: str, query: str, timeout: int = 60, retries: int = 2) -> list:
    """PPDM asset 查 with retry — bypass ppdm._get 的 hardcoded timeout=15。"""
    f = urllib.parse.quote(f'name lk "%{query}%"')
    url = f"https://{ppdm.PPDM_HOST}:{ppdm.PPDM_PORT}/api/v2/assets?pageSize=20&filter={f}"
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {token}")
            res = urllib.request.urlopen(req, context=ppdm._CTX, timeout=timeout)
            return json.loads(res.read()).get("content", [])
        except (TimeoutError, OSError) as e:
            if attempt < retries:
                time.sleep(1.5 ** attempt)
                continue
            raise RuntimeError(f"PPDM lookup '{query}' failed: {e}")


def check_protection(targets: list) -> dict:
    """
    對 IP / hostname / VM-name 查跨平台備份保護狀態。

    回傳 {target: {matched_vm, vm_power, datastores, ppdm, synology, me_replication, errors}}
    """
    result = {t: {
        "matched_vm":     None,
        "vm_power":       None,
        "datastores":     [],
        "ppdm":           None,    # None=找不到 asset; list=找到（多筆都列）
        "synology":       [],
        "me_replication": [],
        "errors":         [],
    } for t in targets}

    # ── vCenter: 找 VM + datastore + ME replication 對應 ─────
    try:
        si = _connect()
        try:
            for t in targets:
                vm = _find_vm(si, t)
                if not vm:
                    continue
                result[t]["matched_vm"]  = vm.name
                result[t]["vm_power"]    = _POWER.get(str(vm.runtime.powerState),
                                                       str(vm.runtime.powerState))
                ds_names = [d.name for d in (vm.datastore or [])]
                result[t]["datastores"]  = ds_names
                for ds in ds_names:
                    if ds in ME_DATASTORE_TO_REPSET:
                        result[t]["me_replication"].append({
                            "datastore": ds,
                            "rep_set":   ME_DATASTORE_TO_REPSET[ds],
                        })
        finally:
            _disconnect(si)
    except Exception as e:
        for t in targets:
            result[t]["errors"].append(f"vCenter: {e}")

    # ── PPDM ────────────────────────────────────────────────
    try:
        token = _ppdm_robust_login()
        try:
            for t in targets:
                # 每個 target 個別 catch — 一次失敗不影響其他
                try:
                    items = _ppdm_lookup(token, t)
                    vm_items = [i for i in items if i.get("type") == "VMWARE_VIRTUAL_MACHINE"]
                    if not vm_items:
                        result[t]["ppdm"] = None
                    else:
                        result[t]["ppdm"] = [{
                            "name":      a.get("name", ""),
                            "status":    a.get("protectionStatus", "?"),
                            "policy":    (a.get("protectionPolicy") or {}).get("name", ""),
                            "last_copy": (a.get("lastAvailableCopyTime") or "")[:16].replace("T", " "),
                        } for a in vm_items]
                except Exception as e:
                    result[t]["errors"].append(f"PPDM lookup: {e}")
        finally:
            try:
                ppdm.logout(token)
            except Exception:
                pass
    except Exception as e:
        for t in targets:
            result[t]["errors"].append(f"PPDM login: {e}")

    # ── Synology ABB ────────────────────────────────────────
    try:
        sid = syno.login()
        try:
            tasks = syno.get_tasks(sid)
        finally:
            syno.logout(sid)
        for t in targets:
            matched_vm = result[t]["matched_vm"]
            for task in tasks:
                for dev in (task.get("devices") or []):
                    host_name = dev.get("host_name", "") or ""
                    host_ip   = dev.get("host_ip", "") or ""
                    if (t in host_name) or (t and t in host_ip) or \
                       (matched_vm and matched_vm in host_name):
                        result[t]["synology"].append({
                            "task_id":   task.get("task_id"),
                            "task_name": task.get("task_name", ""),
                            "device_id": dev.get("device_id"),
                            "host_name": host_name,
                            "os_name":   dev.get("os_name", ""),
                        })
                        break   # 同 task 內一個 device hit 就跳到下個 task
    except Exception as e:
        for t in targets:
            result[t]["errors"].append(f"Synology: {e}")

    return result


def protection_report(targets: list) -> str:
    """格式化文字報告。"""
    data = check_protection(targets)
    lines = ["=" * 80, "  備份保護狀態檢查", "=" * 80]

    for t in targets:
        d = data[t]
        lines.append(f"\n🔍 {t}")

        if d["matched_vm"]:
            lines.append(f"  vCenter VM : {d['matched_vm']}  (power={d['vm_power']})")
            lines.append(f"  Datastore  : {', '.join(d['datastores'])}")
        else:
            lines.append(f"  ⚠️  vCenter 找不到對應的 VM")

        ppdm_failed = any(e.startswith("PPDM") for e in d["errors"])
        if d["ppdm"] is None and ppdm_failed:
            lines.append(f"  PPDM       : ⚠️  查詢失敗（見下方錯誤）")
        elif d["ppdm"] is None:
            lines.append(f"  PPDM       : ❌ 沒有 asset 記錄（從未被 PPDM 看過）")
        else:
            for p in d["ppdm"]:
                icon = "✅" if p["status"] == "PROTECTED" else "❌"
                lines.append(f"  PPDM       : {icon} {p['name']}")
                lines.append(f"               status={p['status']}  policy={p['policy'] or '(無)'}  last={p['last_copy'] or '(無)'}")

        if d["synology"]:
            for s in d["synology"]:
                lines.append(f"  Synology   : ✅ task[{s['task_id']}] \"{s['task_name']}\"  device_id={s['device_id']}")
                lines.append(f"               host={s['host_name']}  os={s['os_name']}")
        else:
            lines.append(f"  Synology   : ❌ 無 ABB 任務涵蓋此目標")

        if d["me_replication"]:
            for r in d["me_replication"]:
                lines.append(f"  ME repl.   : ⚠️  storage HA only — {r['datastore']} → {r['rep_set']}")
            lines.append(f"               （LUN replication 非備份，無時光點還原；只防硬體故障）")
        else:
            lines.append(f"  ME repl.   : (該 datastore 無已知 replication)")

        for e in d["errors"]:
            lines.append(f"  ⚠️  錯誤: {e}")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: backup_audit.py <ip|hostname|vm_name> [<ip2> ...]")
        print("Example: backup_audit.py 10.11.1.62 10.11.1.120 T100RPT")
        sys.exit(1)
    print(protection_report(sys.argv[1:]))
