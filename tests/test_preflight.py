"""Isolation preflight tests."""
import os
import stat
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-pf-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
os.environ["ANONPROXY_LEAKLOG"] = os.path.join(_TMP, "rotate.jsonl")

from anonproxy import preflight  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DATA = _TMP


@pytest.fixture(autouse=True)
def _ctx():
    config.DATA_DIR = Path(_MY_DATA)
    config.DB_PATH = Path(_MY_DATA) / "t.db"
    config.SECRET_KEY_PATH = Path(_MY_DATA) / "secret.key"
    config.DICT_PATH = Path(_MY_DATA) / "dict.yaml"
    config.LEAKLOG_PATH = Path(_MY_DATA) / "rotate.jsonl"
    config.ISOLATION = "warn"
    yield


def _me() -> str:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def test_same_user_is_flagged():
    config.CLIENT_USER = _me()
    problems = preflight.check_isolation()
    assert problems and "SAME user" in problems[0]


def test_unset_client_user_is_flagged():
    config.CLIENT_USER = ""
    problems = preflight.check_isolation()
    assert problems and "not set" in problems[0]


def test_unknown_user_is_flagged():
    config.CLIENT_USER = "no_such_user_zzz"
    problems = preflight.check_isolation()
    assert problems and "not a known OS user" in problems[0]


def test_enforce_raises_when_not_isolated():
    config.CLIENT_USER = _me()
    config.ISOLATION = "enforce"
    with pytest.raises(preflight.IsolationError):
        preflight.run()


def test_harden_permissions():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    key = config.SECRET_KEY_PATH
    key.write_bytes(b"x" * 32)
    os.chmod(key, 0o644)
    preflight.harden_permissions()
    assert stat.S_IMODE(config.DATA_DIR.stat().st_mode) == 0o700
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


def test_can_read_owner_vs_other():
    f = config.DATA_DIR / "probe"
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    f.write_text("x")
    os.chmod(config.DATA_DIR, 0o755)
    os.chmod(f, 0o600)  # owner-only
    # A bogus "other" user (uid that is not the owner, no shared group) cannot read.
    assert preflight._can_read(f, uid=999999, gids={999999}) is False
    os.chmod(f, 0o644)  # world-readable
    assert preflight._can_read(f, uid=999999, gids={999999}) is True
