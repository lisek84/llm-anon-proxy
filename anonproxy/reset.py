"""
Clear collected anonymization data — run this BETWEEN sessions, not during one.

    python -m anonproxy.reset                 # forget all mappings (same key)
    python -m anonproxy.reset --context acme  # forget just one context
    python -m anonproxy.reset --new-key       # also rotate the secret key (new surrogates)
    python -m anonproxy.reset --logs          # also delete rotation + audit logs
    python -m anonproxy.reset --all --yes     # everything, no prompt

What each level means:
  * Forgetting mappings drops the reverse map and history. With the SAME secret
    key the same originals still map to the SAME surrogates (generation is
    deterministic) — so this is a clean-up, not a change of values.
  * --new-key deletes data/secret.key; a fresh random key is generated on the
    next start, so every value now maps to a brand-new surrogate (true rotation).

Stop the proxy before running this: it holds the SQLite file open, and a
mid-session reset would break restoration of surrogates already in flight.
"""
import sys

from .config import config


def _rm(path) -> bool:
    try:
        if path.exists():
            path.unlink()
            return True
    except OSError as exc:
        print(f"  could not remove {path}: {exc}", file=sys.stderr)
    return False


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Clear anonymization data.")
    ap.add_argument("--context", help="reset only this context (default: all)")
    ap.add_argument("--new-key", action="store_true",
                    help="also rotate the secret key (changes all surrogates)")
    ap.add_argument("--logs", action="store_true",
                    help="also delete rotation + audit logs")
    ap.add_argument("--all", action="store_true",
                    help="shorthand for wiping everything in this data dir")
    ap.add_argument("--yes", "-y", action="store_true", help="skip confirmation")
    args = ap.parse_args()

    if args.all:
        args.new_key = True
        args.logs = True
        args.context = None

    plan = []
    if args.context:
        plan.append(f"mappings for context '{args.context}'")
    else:
        plan.append("ALL mappings (every context)")
    if args.new_key:
        plan.append("the secret key (surrogates will all change)")
    if args.logs:
        plan.append("rotation + audit logs")

    print(f"data dir: {config.DATA_DIR}")
    print("about to delete: " + "; ".join(plan))
    if not args.yes:
        if input("proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted.")
            return 1

    # Per-context: SQL delete. Whole wipe: remove the DB files outright.
    if args.context:
        from . import vault
        vault.init()
        n = vault.reset(args.context)
        print(f"  removed {n} mapping(s) for context '{args.context}'")
    else:
        for suffix in ("", "-wal", "-shm"):
            if _rm(config.DB_PATH.with_name(config.DB_PATH.name + suffix)):
                print(f"  removed {config.DB_PATH.name}{suffix}")

    if args.new_key:
        if _rm(config.SECRET_KEY_PATH):
            print("  removed secret.key (a new one is generated on next start)")
    if args.logs:
        for p in (config.LEAKLOG_PATH, config.AUDIT_PATH):
            if _rm(p):
                print(f"  removed {p.name}")

    print("done. Start the proxy again when ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
