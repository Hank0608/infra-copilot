"""Session 模組 — 持有使用者帳密，供 ssh_runner 等 tool 使用。

AD 驗證由目標主機的 PAM/SSSD 處理，client 端不需要自行連 LDAP。
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
import sys; sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")
from tools.secrets import get as _secret

AD_DOMAIN = os.getenv("AD_DOMAIN", "uti.com")


@dataclass
class Session:
    username: str
    password: str
    domain: str = field(default_factory=lambda: AD_DOMAIN)

    @property
    def ssh_user(self) -> str:
        """SSH 登入帳號格式，依主機 SSSD 設定通常用 username@domain。"""
        if "@" in self.username or "\\" in self.username:
            return self.username
        return f"{self.username}@{self.domain}"

    @property
    def ssh_password(self) -> str:
        return self.password

    @property
    def is_valid(self) -> bool:
        return bool(self.username and self.password)


def login(username: str, password: str, domain: str = None) -> Session:
    """建立 Session。實際驗證在 SSH 連線時由目標主機 PAM/SSSD 處理。"""
    return Session(
        username=username,
        password=password,
        domain=domain or AD_DOMAIN,
    )


def from_env() -> Session:
    """從 .env / Keychain 建立 AD Session（AD_USER / AD_PASS）。"""
    return Session(
        username=os.getenv("AD_USER", ""),
        password=_secret("AD_PASS"),
        domain=AD_DOMAIN,
    )


def service_account() -> Session:
    """從 .env / Keychain 建立 service account Session（rp-main 等系統帳號用）。"""
    return Session(
        username=os.getenv("RP_USER", ""),
        password=_secret("RP_PASS"),
        domain="",
    )
