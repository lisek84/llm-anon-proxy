"""
Isolation preflight.

The proxy's on-disk state is a complete de-anonymization oracle:

  * data/mappings.db  — the full original <-> surrogate table
  * dictionary.yaml   — your real values
  * data/secret.key   — derives every surrogate
  * data/rotate.log.jsonl — masked, but still sensitive

If the Claude Code agent runs as the same OS user as the proxy, it can simply
read these files with its normal file tools and reverse everything. No code in
the proxy can prevent a same-UID reader — isolation has to come from the OS.

This module does two things at startup:
  1. Hardens permissions (data dir 0700, secret files 0600).
  2. Checks isolation from ANONPROXY_CLIENT_USER (the user that runs Claude
     Code) and, in 'enforce' mode, refuses to start if that user could read the
     proxy's secrets — including the co-located case (proxy user == client user).

Run standalone:  python -m anonproxy.preflight
"""
import grp
import logging
import os
import pwd
import stat
import sys

from .config import config

log = logging.getLogger("anonproxy.preflight")


class IsolationError(RuntimeError):
    pass


def _sensitive_paths() -> list:
    return [config.DATA_DIR, config.DB_PATH, config.SECRET_KEY_PATH,
            config.DICT_PATH, config.LEAKLOG_PATH]


def harden_permissions() -> None:
    """data dir -> 0700, sensitive files -> 0600 (best effort)."""
    try:
        if config.DATA_DIR.exists():
            os.chmod(config.DATA_DIR, stat.S_IRWXU)  # 0700
    except OSError as exc:
        log.warning("could not chmod data dir: %s", exc)
    for p in (config.DB_PATH, config.SECRET_KEY_PATH, config.DICT_PATH, config.LEAKLOG_PATH):
        try:
            if p.exists():
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError as exc:
            log.warning("could not chmod %s: %s", p, exc)


def _user_ids(username: str) -> tuple[int, set[int]] | None:
    """Return (uid, set of gids) for username, or None if unknown."""
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return None
    gids = {pw.pw_gid}
    for g in grp.getgrall():
        if username in g.gr_mem:
            gids.add(g.gr_gid)
    return pw.pw_uid, gids


def _can_read(path, uid: int, gids: set[int]) -> bool:
    """Would a user with this uid/gids be able to read `path`?

    Checks the file's own bits plus traverse (x) on every parent directory —
    a file is only reachable if each ancestor dir is executable by the user.
    """
    try:
        st = path.stat()
    except OSError:
        return False

    def readable(st_, want_r) -> bool:
        mode = st_.st_mode
        if st_.st_uid == uid:
            return bool(mode & (stat.S_IRUSR if want_r else stat.S_IXUSR))
        if st_.st_gid in gids:
            return bool(mode & (stat.S_IRGRP if want_r else stat.S_IXGRP))
        return bool(mode & (stat.S_IROTH if want_r else stat.S_IXOTH))

    # Need read on the file itself.
    if not readable(st, want_r=True):
        return False
    # Need execute/search on every ancestor directory.
    p = path.resolve()
    for parent in p.parents:
        try:
            pst = parent.stat()
        except OSError:
            return False
        if not readable(pst, want_r=False):
            return False
        if parent == parent.parent:  # reached root
            break
    return True


def check_isolation() -> list[str]:
    """Return a list of human-readable isolation problems (empty = looks ok)."""
    problems: list[str] = []
    proxy_uid = os.getuid()
    proxy_user = pwd.getpwuid(proxy_uid).pw_name

    client = config.CLIENT_USER.strip()
    if not client:
        problems.append(
            "ANONPROXY_CLIENT_USER is not set — cannot verify the agent is isolated. "
            "Set it to the OS user that runs Claude Code.")
        return problems

    if client == proxy_user:
        problems.append(
            f"proxy runs as the SAME user ('{proxy_user}') that runs Claude Code — "
            f"the agent can read the vault and reverse everything. Run the proxy as a "
            f"different user / container / host.")
        return problems

    ids = _user_ids(client)
    if ids is None:
        problems.append(f"ANONPROXY_CLIENT_USER '{client}' is not a known OS user.")
        return problems
    cuid, cgids = ids
    for p in _sensitive_paths():
        if p.exists() and _can_read(p, cuid, cgids):
            problems.append(f"client user '{client}' can read {p}")
    return problems


def run(reason_exit: bool = True) -> list[str]:
    """Harden perms and evaluate isolation according to config.ISOLATION."""
    harden_permissions()
    mode = config.ISOLATION
    if mode == "off":
        log.warning("isolation check disabled (ANONPROXY_ISOLATION=off)")
        return []

    problems = check_isolation()
    if not problems:
        log.info("isolation OK: client user '%s' cannot read the proxy's secrets",
                 config.CLIENT_USER or "?")
        return []

    banner = "=" * 70
    log.warning(banner)
    log.warning("ISOLATION WARNING — the Claude Code agent may be able to read")
    log.warning("the proxy's de-anonymization data, which defeats this tool:")
    for pb in problems:
        log.warning("  - %s", pb)
    log.warning("Fix: run the proxy as a dedicated user / container / WSL distro /")
    log.warning("host that Claude Code's file tools cannot reach. See docs/THREAT-MODEL.md")
    log.warning(banner)

    if mode == "enforce" and reason_exit:
        raise IsolationError("; ".join(problems))
    return problems


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        probs = run(reason_exit=False)
    except Exception as exc:  # noqa: BLE001
        print(f"preflight error: {exc}")
        sys.exit(2)
    sys.exit(1 if probs else 0)
