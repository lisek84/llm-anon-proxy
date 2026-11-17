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


def _state() -> tuple[str, dict]:
    """Three distinct states, so a read error can't silently open the dashboard:
      ('open',  {})     — no viewer file / no viewers: dashboard is open (by design)
      ('auth',  users)  — viewers configured: login required
      ('error', {})     — file exists but is unreadable/corrupt: FAIL CLOSED (deny)
    """
    p = _path()
    if not p.exists():
        return "open", {}
    try:
        users = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "error", {}
    if not isinstance(users, dict) or not users:
        return "open", {}
    return "auth", users


def _save(users: dict) -> None:
    import tempfile
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic: write a sibling temp file, fix its mode, then rename over the target
    # so a crash mid-write can never leave ui-users.json truncated/corrupt.
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".ui-users.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        os.replace(tmp, p)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
    """Login is required when viewers are configured — or when the viewer file
    exists but can't be read (fail closed)."""
    return _state()[0] != "open"


def _verify_rec(rec: dict, password: str) -> bool:
    try:
        salt = bytes.fromhex(rec["salt"])
    except (KeyError, TypeError, ValueError):
        return False
    expected = rec.get("hash", "")
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                              int(rec.get("iters", _ITERATIONS))).hex()
    return hmac.compare_digest(got, expected)


def verify(user: str, password: str) -> bool:
    rec = _load().get(user)
    return bool(rec) and _verify_rec(rec, password)


def challenge_if_needed(request: Request) -> Response | None:
    """Return a 401/503 Response if access is not allowed, else None."""
    state, users = _state()
    if state == "open":
        return None
    if state == "error":
        # The viewer file exists but is unreadable/corrupt — do NOT fall back to
        # an open dashboard; refuse until an admin fixes it.
        return Response(status_code=503, media_type="text/plain",
                        content="dashboard auth config is unreadable — access refused")
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8", "replace")
            user, _, password = raw.partition(":")
            rec = users.get(user)
            if rec and _verify_rec(rec, password):
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
        if len(pw) < 8:
            print("please use at least 8 characters")
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
