"""Tiny JSON-backed history store for the web UI (SQLite is a future upgrade)."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .config import DATA_DIR
from .models import RenewalRecord

_HISTORY = DATA_DIR / "history.json"
_LOCK = threading.Lock()
_MAX = 500


def _read() -> list[dict]:
    if not _HISTORY.exists():
        return []
    try:
        return json.loads(_HISTORY.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def add_record(record: RenewalRecord) -> None:
    with _LOCK:
        items = _read()
        items.append(record.as_dict())
        items = items[-_MAX:]
        _HISTORY.parent.mkdir(parents=True, exist_ok=True)
        _HISTORY.write_text(json.dumps(items, indent=2))


def all_records() -> list[dict]:
    return list(reversed(_read()))


def latest_for(server_id: str) -> dict | None:
    for rec in reversed(_read()):
        if rec.get("server_id") == server_id:
            return rec
    return None
