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
async def test_fail_open_degradation_emits_dashboard_notice():
    from anonproxy import events
    config.LLM_FAIL_CLOSED = False
    main._last_llm_degrade_notice = 0.0        # reset the throttle
    before = events.snapshot()["notices"]
    await main._anon_text("visit example.com now", "test")
    assert events.snapshot()["notices"] > before   # degradation is visible


@pytest.mark.asyncio
async def test_fail_closed_raises():
    config.LLM_FAIL_CLOSED = True
    with pytest.raises(llm_detector.LLMUnavailable):
        await main._anon_text("visit example.com now", "test")


# ── Ollama response validation (no HTTP; parse layer directly) ────────────────

def test_valid_json_without_entities_key_is_a_failure():
    # {"status":"ok"} is syntactically fine but omits `entities` — must raise,
    # not be mistaken for an empty "nothing found" result (would KeyError later).
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._parse_entities('{"status":"ok"}', "some host text here")


def test_entities_not_a_list_is_a_failure():
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._parse_entities('{"entities":"nope"}', "some host text here")


def test_empty_entities_is_a_normal_empty_result():
    assert llm_detector._parse_entities('{"entities":[]}', "text") == []


@pytest.mark.parametrize("payload", [
    {"message": None},                 # 200 OK but message is null → AttributeError before
    {},                                # no message key
    {"message": {"content": 123}},     # content not a string
    {"message": "oops"},               # message not an object
    "not even a dict",
])
def test_malformed_ollama_200_is_llm_unavailable(payload):
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._message_content(payload)


def test_valid_ollama_message_content_returned():
    assert llm_detector._message_content({"message": {"content": '{"entities":[]}'}}) \
        == '{"entities":[]}'


def test_malformed_entity_element_raises():
    # A non-string field or a missing `type` is a detector malfunction — raise
    # (so fail-closed blocks) instead of treating it as "nothing found".
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._parse_entities(
            '{"entities":[{"text":123,"type":"HOSTNAME"}]}', "x")
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._parse_entities('{"entities":[{"text":"DC01"}]}', "host DC01 here")


def test_wellformed_but_unusable_entity_is_skipped_not_raised():
    # Correct shape, but the text isn't in the input / type we don't anonymize:
    # that's benign variance, not a malfunction — skip without raising.
    raw = '{"entities":[{"text":"not-in-input","type":"HOSTNAME"},' \
          '{"text":"of-db01","type":"WEATHER"}]}'
    assert llm_detector._parse_entities(raw, "connect to of-db01 now") == []
