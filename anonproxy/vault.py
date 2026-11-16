"""
SQLite-backed mapping store (original <-> surrogate), isolated per context.

Guarantees:
  * The same original always maps to the same surrogate within a context
    (deterministic, persisted).
  * A surrogate is never shared by two different originals within a context
    (uniqueness enforced on insert — the reverse map is unambiguous, so a
    deanonymized command can never be routed to the wrong host).
"""
import sqlite3
import threading
from pathlib import Path

from .config import config

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
generation: int = 0  # bumped on init()/reset() so caches can invalidate


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS mappings (
            context     TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            original    TEXT NOT NULL,
            surrogate   TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (context, original)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ctx_surrogate
            ON mappings(context, surrogate);
        CREATE INDEX IF NOT EXISTS idx_ctx
            ON mappings(context);
        """
    )
    conn.commit()
    return conn


def init(db_path: Path | None = None) -> None:
    global _conn, generation
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = _connect(db_path)
        generation += 1


def _c() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


def reset(context: str | None = None) -> int:
    """Delete stored mappings and return how many rows were removed.

    context=None  → wipe every context (a full forget).
    context="x"   → wipe only that context.
    Deterministic surrogate generation is unaffected: with the same secret key,
    the same originals would map to the same surrogates again. To also change the
    surrogate values, rotate the secret key (see anonproxy.reset).
    """
    global generation
    with _lock:
        generation += 1
        conn = _c()
        if context is None:
            n = conn.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]
            conn.execute("DELETE FROM mappings")
        else:
            n = conn.execute(
                "SELECT COUNT(*) FROM mappings WHERE context=?", (context,)
            ).fetchone()[0]
            conn.execute("DELETE FROM mappings WHERE context=?", (context,))
        conn.commit()
    return n


def lookup_surrogate(original: str, context: str | None = None) -> str | None:
    ctx = context or config.CONTEXT_ID
    with _lock:
        row = _c().execute(
            "SELECT surrogate FROM mappings WHERE context=? AND original=?",
            (ctx, original),
        ).fetchone()
    return row[0] if row else None


def surrogate_exists(surrogate: str, context: str | None = None) -> bool:
    ctx = context or config.CONTEXT_ID
    with _lock:
        row = _c().execute(
            "SELECT 1 FROM mappings WHERE context=? AND surrogate=?",
            (ctx, surrogate),
        ).fetchone()
    return row is not None


def get_or_create(original: str, entity_type: str, surrogate_fn, context: str | None = None) -> tuple[str, bool]:
    """
    Return (surrogate, is_new).

    surrogate_fn(original, entity_type, attempt) -> candidate surrogate.
    It is called with increasing `attempt` until a collision-free surrogate is
    found, so two different originals can never collide on one surrogate.
    """
    ctx = context or config.CONTEXT_ID
    with _lock:
        conn = _c()
        row = conn.execute(
            "SELECT surrogate FROM mappings WHERE context=? AND original=?",
            (ctx, original),
        ).fetchone()
        if row:
            return row[0], False

        attempt = 0
        while True:
            candidate = surrogate_fn(original, entity_type, attempt)
            clash = conn.execute(
                "SELECT original FROM mappings WHERE context=? AND surrogate=?",
                (ctx, candidate),
            ).fetchone()
            if clash is None:
                break
            if clash[0] == original:
                return candidate, False
            attempt += 1
            if attempt > 100000:
                raise RuntimeError("could not generate a unique surrogate")

        conn.execute(
            "INSERT INTO mappings (context, entity_type, original, surrogate) VALUES (?,?,?,?)",
            (ctx, entity_type, original, candidate),
        )
        conn.commit()
        return candidate, True


def all_reverse_mappings(context: str | None = None) -> list[tuple[str, str]]:
    """Return (surrogate, original) pairs, longest surrogate first."""
    ctx = context or config.CONTEXT_ID
    with _lock:
        rows = _c().execute(
            "SELECT surrogate, original FROM mappings WHERE context=? "
            "ORDER BY LENGTH(surrogate) DESC",
            (ctx,),
        ).fetchall()
    return rows


def stats(context: str | None = None) -> dict[str, int]:
    ctx = context or config.CONTEXT_ID
    with _lock:
        rows = _c().execute(
            "SELECT entity_type, COUNT(*) FROM mappings WHERE context=? GROUP BY entity_type",
            (ctx,),
        ).fetchall()
    return {r[0]: r[1] for r in rows}
