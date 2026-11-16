"""
When the LLM layer is enabled but Ollama is down:
  * fail-closed (default): the request is blocked (LLMUnavailable propagates),
    never forwarded half-anonymized;
  * fail-open: degrade to dictionary+regex for the whole request — still fully
    anonymized by the deterministic layers, no partial state.
"""
import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-degrade-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write("domains:\n  - example.com\n")

from anonproxy import main, llm_detector, vault, dictionary  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]


@pytest.fixture(autouse=True)
def _ctx(monkeypatch):
    config.CONTEXT_ID = "degrade"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.AUDIT_ENABLED = False
    config.LLM_ENABLED = True

    async def _boom(_text):
        raise llm_detector.LLMUnavailable("ollama down")

    monkeypatch.setattr(llm_detector, "detect", _boom)
    vault.init()
    dictionary.load()
    yield


@pytest.mark.asyncio
async def test_fail_open_degrades_to_regex_dict():
    config.LLM_FAIL_CLOSED = False
    out = await main._anon_text("visit example.com now", "test")
    assert "example.com" not in out          # still anonymized by the dictionary
    assert out != "visit example.com now"


@pytest.mark.asyncio
async def test_fail_closed_raises():
    config.LLM_FAIL_CLOSED = True
    with pytest.raises(llm_detector.LLMUnavailable):
        await main._anon_text("visit example.com now", "test")
