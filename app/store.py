"""Tiny JSON-backed history store for the web UI (SQLite is a future upgrade).

The history file lives next to servers.json in the persistent config
directory (HISTORY_FILE overrides). Earlier releases wrote it to
DATA_DIR/history.json, which is not covered by the documented bind mounts;
preflight copies that legacy file forward once if the new one is absent.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .config import DATA_DIR, SERVERS_FILE
from .models import RenewalRecord

HISTORY_FILE = Path(os.environ.get("HISTORY_FILE") or (SERVERS_FILE.parent / "history.json"))
LEGACY_HISTORY_FILE = DATA_DIR / "history.json"
_LOCK = threading.Lock()
_MAX = 500


def _read() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def add_record(record: RenewalRecord) -> None:
    with _LOCK:
        items = _read()
        items.append(record.as_dict())
        items = items[-_MAX:]
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(items, indent=2))


def all_records() -> list[dict]:
    return list(reversed(_read()))


def latest_for(server_id: str) -> dict | None:
    for rec in reversed(_read()):
        if rec.get("server_id") == server_id:
            return rec
    return None
