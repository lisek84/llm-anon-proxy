"""Reset / rotation behaviour of the vault and secret key."""
import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-reset-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")

from anonproxy import vault, surrogates  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.path.join(_TMP, "t.db")


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "resettest"
    config.DB_PATH = Path(_MY_DB)
    config.SECRET_KEY_PATH = Path(_TMP) / "secret.key"
    vault.init()
    yield


def test_reset_forgets_but_same_key_regenerates_same_surrogate():
    s1, new1 = vault.get_or_create("1.2.3.4", "IP_ADDRESS", surrogates.generate)
    assert new1
    removed = vault.reset("resettest")
    assert removed == 1
    assert vault.lookup_surrogate("1.2.3.4") is None
    # Same key → same surrogate again (deterministic): a clean-up, not a change.
    s2, new2 = vault.get_or_create("1.2.3.4", "IP_ADDRESS", surrogates.generate)
    assert new2 and s2 == s1


def test_new_key_changes_surrogate():
    s1, _ = vault.get_or_create("9.9.9.9", "IP_ADDRESS", surrogates.generate)
    vault.reset("resettest")
    # Rotate the secret key: delete the file and clear the in-memory cache.
    config.SECRET_KEY_PATH.unlink(missing_ok=True)
    surrogates._secret = None
    s2, _ = vault.get_or_create("9.9.9.9", "IP_ADDRESS", surrogates.generate)
    assert s2 != s1


def test_reset_all_contexts():
    vault.get_or_create("a.b.c.d", "IP_ADDRESS", surrogates.generate, context="c1")
    vault.get_or_create("e.f.g.h", "IP_ADDRESS", surrogates.generate, context="c2")
    removed = vault.reset(None)  # all contexts
    assert removed >= 2
    assert vault.lookup_surrogate("a.b.c.d", context="c1") is None
    assert vault.lookup_surrogate("e.f.g.h", context="c2") is None
