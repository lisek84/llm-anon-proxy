"""
In-memory event bus for the live dashboard.

A bounded ring buffer of recent events with monotonically increasing ids, so the
web UI can poll/stream "everything since id N". Nothing is persisted here (the
durable record is the audit log); this is purely for the live view, and it holds
real values in memory only — the HTTP layer decides whether to mask them.
"""
import itertools
import threading
import time
from collections import deque

_lock = threading.Lock()
_events: deque = deque(maxlen=1000)
_counter = itertools.count(1)
_stats: dict[str, int] = {}     # entity type -> number of distinct catches
_requests = 0


def emit_catch(source: str, entity_type: str, original: str, surrogate: str) -> None:
    with _lock:
        _events.append({
            "id": next(_counter), "kind": "catch", "ts": time.time(),
            "source": source, "type": entity_type,
            "original": original, "surrogate": surrogate,
        })
        _stats[entity_type] = _stats.get(entity_type, 0) + 1


def emit_request(model: str, restored: int, anon: int = 0, anon_new: int = 0) -> None:
    global _requests
    with _lock:
        _requests += 1
        _events.append({
            "id": next(_counter), "kind": "request", "ts": time.time(),
            "model": model, "restored": restored, "anon": anon, "anon_new": anon_new,
        })


_notices = 0


def emit_notice(message: str, detail: str = "") -> None:
    """Something was forwarded WITHOUT anonymization (unscannable block, unknown
    endpoint). Surfaced on the dashboard and counted, once per occurrence."""
    global _notices
    with _lock:
        _notices += 1
        _events.append({
            "id": next(_counter), "kind": "notice", "ts": time.time(),
            "message": message, "detail": detail,
        })


def since(after_id: int) -> list[dict]:
    with _lock:
        return [e for e in _events if e["id"] > after_id]


def snapshot(limit: int = 200) -> dict:
    with _lock:
        recent = list(_events)[-limit:]
        return {
            "stats": dict(_stats),
            "requests": _requests,
            "notices": _notices,
            "last_id": _events[-1]["id"] if _events else 0,
            "recent": recent,
        }
