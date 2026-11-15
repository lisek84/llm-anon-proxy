"""
Audit trail — the human-readable record of what the proxy actually caught.

One JSONL line per value the first time it is seen, with the real original and
its surrogate, the entity type, and where it appeared (system / message /
tool_use / tool_result). This is sensitive (it holds real values), so it is
written to the protected data dir with 0600 perms and is never served over HTTP.

Review it with:   python -m anonproxy.audit
"""
import json
import os
import stat
import threading
from collections import Counter
from datetime import datetime, timezone

from .config import config

_lock = threading.Lock()


def record(original: str, surrogate: str, entity_type: str, source: str) -> None:
    """Append one catch event. Called only for newly-created mappings."""
    if not config.AUDIT_ENABLED:
        return
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "context": config.CONTEXT_ID,
        "source": source,
        "type": entity_type,
        "original": original,
        "surrogate": surrogate,
    }
    path = config.AUDIT_PATH
    with _lock:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            new_file = not path.exists()
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if new_file:
                try:
                    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
                except OSError:
                    pass
        except OSError:
            pass


def read_all(context: str | None = None) -> list[dict]:
    ctx = context or config.CONTEXT_ID
    path = config.AUDIT_PATH
    out: list[dict] = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("context") == ctx:
                out.append(e)
    return out


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Show what the proxy has caught.")
    ap.add_argument("-n", "--limit", type=int, default=0, help="show only the last N (0 = all)")
    ap.add_argument("--context", default=None, help="context id (default: current)")
    args = ap.parse_args()

    entries = read_all(args.context)
    if not entries:
        print(f"No audit entries yet at {config.AUDIT_PATH}")
        return 0

    by_type = Counter(e["type"] for e in entries)
    shown = entries[-args.limit:] if args.limit else entries

    print(f"context: {args.context or config.CONTEXT_ID}   caught {len(entries)} distinct value(s)")
    print("by type: " + ", ".join(f"{t}={n}" for t, n in by_type.most_common()))
    print("-" * 78)
    for e in shown:
        print(f"{e['ts']}  [{e['type']:12}] {e['source']:11}  "
              f"{e['original']!r}  ->  {e['surrogate']!r}")
    print("-" * 78)
    print(f"file: {config.AUDIT_PATH}  (real values — keep private)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
