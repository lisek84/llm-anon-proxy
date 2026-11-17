"""
Optional HTTP Basic auth for the dashboard (/ui).

Open by default. The moment you add a viewer with `python -m anonproxy.uiauth`,
the dashboard starts requiring that login — no env var needed. Credentials are
stored as PBKDF2-HMAC-SHA256 hashes in data/ui-users.json (0600), never in clear.

    python -m anonproxy.uiauth add alice     # prompts for a password; enables login
    python -m anonproxy.uiauth list
    python -m anonproxy.uiauth remove alice
    python -m anonproxy.uiauth disable       # delete all viewers -> dashboard open again

Pair this with ANONPROXY_TLS (or a TLS-terminating reverse proxy) whenever the
dashboard is reachable off-loopback — Basic auth over plain HTTP sends the
password reversibly.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import stat

from fastapi import Request, Response

from .config import config

_ITERATIONS = 200_000


def _path():
    return config.DATA_DIR / "ui-users.json"


def _load() -> dict:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(users: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(users, indent=2), encoding="utf-8")
    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS).hex()


def add_user(user: str, password: str) -> None:
    users = _load()
    salt = secrets.token_bytes(16)
    users[user] = {"salt": salt.hex(), "hash": _hash(password, salt), "iters": _ITERATIONS}
    _save(users)


def remove_user(user: str) -> bool:
    users = _load()
    if user in users:
        del users[user]
        _save(users)
        return True
    return False


def disable() -> None:
    try:
        _path().unlink()
    except FileNotFoundError:
        pass


def required() -> bool:
    """Login is required exactly when at least one viewer exists."""
    return bool(_load())


def verify(user: str, password: str) -> bool:
    rec = _load().get(user)
    if not rec:
        return False
    try:
        salt = bytes.fromhex(rec["salt"])
    except (KeyError, ValueError):
        return False
    expected = rec.get("hash", "")
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                              int(rec.get("iters", _ITERATIONS))).hex()
    return hmac.compare_digest(got, expected)


def challenge_if_needed(request: Request) -> Response | None:
    """Return a 401 Response if the request lacks valid Basic auth, else None."""
    if not required():
        return None
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8", "replace")
            user, _, password = raw.partition(":")
            if verify(user, password):
                return None
        except (binascii.Error, ValueError):
            pass
    return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="anonproxy"'},
                   content="Authentication required", media_type="text/plain")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> int:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(description="Manage dashboard (/ui) viewers.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="add/update a viewer (enables login)")
    a.add_argument("user")
    r = sub.add_parser("remove", help="remove a viewer")
    r.add_argument("user")
    sub.add_parser("list", help="list viewers")
    sub.add_parser("disable", help="remove all viewers (dashboard open again)")
    args = ap.parse_args()

    if args.cmd == "add":
        pw = getpass.getpass(f"password for {args.user!r}: ")
        if pw != getpass.getpass("repeat: "):
            print("passwords do not match")
            return 1
        if len(pw) < 6:
            print("please use at least 6 characters")
            return 1
        add_user(args.user, pw)
        print(f"added viewer {args.user!r} — the dashboard now requires login.")
    elif args.cmd == "remove":
        print("removed." if remove_user(args.user) else "no such viewer.")
        if not required():
            print("no viewers left — the dashboard is open again.")
    elif args.cmd == "list":
        users = _load()
        print("\n".join(sorted(users)) if users else "(no viewers — dashboard is open)")
    elif args.cmd == "disable":
        disable()
        print("all viewers removed — the dashboard is open again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
