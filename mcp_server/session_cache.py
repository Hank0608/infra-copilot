"""通用 token/session 快取。

Zabbix/Wazuh/PPDM/Synology/FortiGate 的 login() 各自回傳不同形狀的值
（字串 token、JWT、sid、或 {cookie, csrf} dict）；這裡不關心形狀，
單純依名稱快取「login_fn() 的回傳值」，過期或失敗時重新登入。
"""

import time
from threading import Lock

_cache: dict[str, tuple[object, float]] = {}
_lock = Lock()


def get_token(name: str, login_fn, ttl: int = 300):
    """回傳快取的值；不存在或超過 ttl 秒就呼叫 login_fn() 重新取得並快取。"""
    with _lock:
        cached = _cache.get(name)
        if cached is not None:
            value, ts = cached
            if time.time() - ts < ttl:
                return value
        value = login_fn()
        _cache[name] = (value, time.time())
        return value


def invalidate(name: str) -> None:
    """清掉快取，強制下次 get_token 重新登入（例如收到認證錯誤之後）。"""
    with _lock:
        _cache.pop(name, None)


def call_with_retry(name: str, login_fn, fn, *args, **kwargs):
    """呼叫 fn(token, *args, **kwargs)；失敗時清快取、重新登入後重試一次。"""
    token = get_token(name, login_fn)
    try:
        return fn(token, *args, **kwargs)
    except Exception:
        invalidate(name)
        token = get_token(name, login_fn)
        return fn(token, *args, **kwargs)
