"""
Review the rotation log:  python -m anonproxy.rotate

Prints each distinct secret-shaped value that was seen during sessions, grouped
by category, so you can walk the list and rotate credentials afterwards. The log
stores only a type, a masked preview and a hash — never the full value.
"""
import json
import sys
from collections import defaultdict

from .config import config


def main() -> int:
    path = config.LEAKLOG_PATH
    if not path.exists():
        print(f"No rotation log yet at {path}")
        return 0

    by_cat: dict[str, list[dict]] = defaultdict(list)
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_cat[e.get("category", "?")].append(e)

    order = ["leaked", "intercepted"]
    cats = order + [c for c in by_cat if c not in order]
    total = 0
    for cat in cats:
        entries = by_cat.get(cat)
        if not entries:
            continue
        # Dedup by sha256, keep newest.
        uniq: dict[str, dict] = {}
        for e in entries:
            uniq[e.get("sha256", id(e))] = e
        header = {
            "leaked": "LEAKED — reached the API, rotate these",
            "intercepted": "INTERCEPTED — replaced before sending, rotate as precaution",
        }.get(cat, cat)
        print(f"\n=== {header} ({len(uniq)}) ===")
        for e in sorted(uniq.values(), key=lambda x: x.get("ts", "")):
            total += 1
            print(f"  [{e.get('type','?'):10}] {e.get('preview',''):28} "
                  f"first seen {e.get('ts','?')}  ctx={e.get('context','?')}  "
                  f"src={e.get('source','')}  sha256={e.get('sha256','')[:12]}")
    if total == 0:
        print("Rotation log is empty.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
