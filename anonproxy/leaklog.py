"""
Rotation log: an append-only JSONL record of every secret-shaped value seen,
so that after a session you can walk the file and rotate what was exposed.

Two categories:
  * "intercepted" — a secret was detected and replaced before leaving the
    machine. It still touched local logs/history, so rotating it is prudent.
  * "leaked"      — a secret was found in the bytes actually sent upstream
    (post-anonymization scan). This one definitely reached the API: rotate it.

The log never stores the full value. It stores a type, a short masked preview,
a SHA-256 hash (to dedupe and to let you match it later), and context.
"""
import hashlib
import json
import logging
import os
import stat
import threading
from datetime import datetime, timezone

from .config import config

log = logging.getLogger("anonproxy.leaklog")
_lock = threading.Lock()
_seen_hashes: set[str] = set()


def _mask(value: str) -> str:
    if len(value) <= 6:
        return value[0] + "***"
    return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"


def _ensure_perms(path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def record(value: str, entity_type: str, category: str, source: str = "") -> None:
    """Append one rotation entry. Deduped per process by (hash, category)."""
    if not value:
        return
    h = hashlib.sha256(value.encode()).hexdigest()
    dedupe_key = f"{category}:{h}"
    with _lock:
        if dedupe_key in _seen_hashes:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "context": config.CONTEXT_ID,
            "category": category,
            "type": entity_type,
            "preview": _mask(value),
            "sha256": h,
            "source": source,
        }
        # Best-effort: a failed write must never break the request path, and the
        # value is marked seen only AFTER a successful write so a later attempt
        # can still record it.
        try:
            path = config.LEAKLOG_PATH
            path.parent.mkdir(parents=True, exist_ok=True)
            new_file = not path.exists()
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if new_file:
                _ensure_perms(path)
            _seen_hashes.add(dedupe_key)
        except OSError:
            log.exception("non-fatal: could not write rotation log")


# Entity types considered "secret-shaped" and worth rotating.
ROTATABLE = frozenset({"CREDENTIAL", "TOKEN", "HASH"})
