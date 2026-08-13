"""Single-admin authentication for the web UI.

Everything lives next to servers.json in the writable /config mount, so it
persists across container rebuilds:

    <config>/admin.json       the admin credential (PBKDF2-SHA256, chmod 600)
    <config>/session.secret   HMAC key for signing session cookies (chmod 600)

No external dependencies — password hashing and cookie signing use hashlib/hmac
from the standard library.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from .. import config

PBKDF2_ITERATIONS = 240_000
SESSION_TTL = 8 * 3600  # seconds
COOKIE_NAME = "session"
MIN_PASSWORD_LEN = 8


def _auth_dir() -> Path:
    d = config.SERVERS_FILE.parent
    d.mkdir(parents=True, exist_ok=True)
    return d


def _admin_path() -> Path:
    return _auth_dir() / "admin.json"


def _lock_down(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# admin credential
# --------------------------------------------------------------------------- #
def needs_setup() -> bool:
    """True until an admin account exists (drives the first-run Setup flow)."""
    return not _admin_path().exists()


def create_admin(username: str, password: str) -> None:
    rec = {
        "username": username,
        "algo": "pbkdf2_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": secrets.token_hex(16),
        "hash": "",
    }
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), rec["iterations"])
    rec["hash"] = dk.hex()
    _admin_path().write_text(json.dumps(rec, indent=2) + "\n")
    _lock_down(_admin_path())


def verify(username: str, password: str) -> bool:
    p = _admin_path()
    if not p.exists():
        return False
    try:
        rec = json.loads(p.read_text())
    except Exception:
        return False
    if not hmac.compare_digest(rec.get("username", ""), username):
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(rec["salt"]), int(rec["iterations"])
    )
    return hmac.compare_digest(dk.hex(), rec.get("hash", ""))


# --------------------------------------------------------------------------- #
# signed session tokens
# --------------------------------------------------------------------------- #
def _session_secret() -> bytes:
    p = _auth_dir() / "session.secret"
    if p.exists():
        return p.read_bytes()
    sec = secrets.token_bytes(32)
    p.write_bytes(sec)
    _lock_down(p)
    return sec


def make_token(username: str) -> str:
    payload = f"{username}|{int(time.time())}"
    sig = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{b64}.{sig}"


def read_token(token: str) -> str | None:
    """Return the username if the token is valid and unexpired, else None."""
    if not token or "." not in token:
        return None
    try:
        b64, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(b64.encode()).decode()
        expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        username, ts = payload.split("|", 1)
        if int(time.time()) - int(ts) > SESSION_TTL:
            return None
        return username
    except Exception:
        return None
