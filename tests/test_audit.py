"""Audit trail records new catches with real original -> surrogate."""
import json
import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-audit-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")

with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write("domains:\n  - example.com\n")

from anonproxy import vault, dictionary, anonymizer, audit  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY = _TMP


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "audittest"
    config.DB_PATH = Path(_MY) / "t.db"
    config.DICT_PATH = Path(_MY) / "dict.yaml"
    config.AUDIT_PATH = Path(_MY) / "audit.jsonl"
    config.AUDIT_ENABLED = True
    config.LLM_ENABLED = False
    if config.AUDIT_PATH.exists():
        config.AUDIT_PATH.unlink()
    vault.init()
    dictionary.load()
    yield


def test_audit_records_new_catch_once():
    anonymizer.anonymize("deploy example.com and 185.12.34.56", source="message")
    # Second time: same values are cached, so no new audit rows.
    anonymizer.anonymize("again example.com and 185.12.34.56", source="tool_result")

    entries = audit.read_all("audittest")
    originals = {e["original"] for e in entries}
    assert "example.com" in originals
    assert "185.12.34.56" in originals
    # Each distinct value recorded exactly once (new mappings only).
    assert len(entries) == len(originals)
    for e in entries:
        assert e["surrogate"] and e["surrogate"] != e["original"]
        assert e["type"] in ("DOMAIN", "IP_ADDRESS")


def test_audit_file_is_private():
    anonymizer.anonymize("connect 198.51.77.88", source="message")  # fresh value
    import stat
    mode = stat.S_IMODE(config.AUDIT_PATH.stat().st_mode)
    assert mode == 0o600
