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
async def test_llm_skipped_for_system_and_tools(monkeypatch):
    # The contextual LLM layer must NOT run on Claude Code's system prompt / tool
    # schemas (boilerplate a small model floods with false positives) — only on
    # message/tool_result prose.
    seen = []

    async def _spy(text):
        seen.append(text)
        return []

    monkeypatch.setattr(llm_detector, "detect", _spy)
    config.LLM_ENABLED = True
    config.LLM_FAIL_CLOSED = False
    await main._anon_text("a boilerplate instruction line", "system")
    await main._anon_text("a tool description sentence", "tools")
    assert seen == []                                   # not consulted for those
    await main._anon_text("a user prose line long enough", "message")
    assert len(seen) == 1                               # consulted for messages


def test_inject_hint_opt_in_and_shapes(monkeypatch):
    monkeypatch.setattr(config, "INJECT_HINT", True)
    b = {"system": "orig"}; main._inject_hint(b)
    assert b["system"].startswith("orig\n\n") and "placeholders" in b["system"]
    b = {"system": [{"type": "text", "text": "x"}]}; main._inject_hint(b)
    assert len(b["system"]) == 2 and "placeholders" in b["system"][1]["text"]
    b = {}; main._inject_hint(b)
    assert isinstance(b["system"], str) and "placeholders" in b["system"]
    monkeypatch.setattr(config, "INJECT_HINT", False)
    b = {"system": "orig"}; main._inject_hint(b)
    assert b["system"] == "orig"            # off by default → untouched


def test_inject_hint_explains_shape_preservation():
    # The hint must tell the model that surrogates keep the shape of the
    # original, so it trusts the form and uses each value verbatim.
    assert "shape of what it replaces" in main._HINT_TEXT
    assert "exactly in the form given" in main._HINT_TEXT


@pytest.mark.asyncio
async def test_fail_closed_raises():
    config.LLM_FAIL_CLOSED = True
    with pytest.raises(llm_detector.LLMUnavailable):
        await main._anon_text("visit example.com now", "test")


# ── Ollama response validation (no HTTP; parse layer directly) ────────────────

def test_offschema_but_parseable_is_empty_not_failure():
    # A small model routinely returns valid JSON that doesn't follow the schema
    # ({"status":"ok"}, a non-list entities, …). The deterministic layers still
    # ran, so this is best-effort "nothing found" — NOT an outage that blocks the
    # whole request. Only an UNPARSEABLE reply raises (fail-closed).
    assert llm_detector._parse_entities('{"status":"ok"}', "some host text here") == []
    assert llm_detector._parse_entities('{"entities":"nope"}', "some host text here") == []
    assert llm_detector._parse_entities('[]', "text") == []
    with pytest.raises(llm_detector.LLMUnavailable):
        llm_detector._parse_entities('this is not json {{{', "text")


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


def test_odd_entity_elements_are_skipped_not_fatal():
    # Odd elements (non-string field, missing type) are skipped, and well-formed
    # ones in the same reply are still extracted — one bad element must not block
    # the whole request.
    raw = '{"entities":[{"text":123,"type":"HOSTNAME"},{"text":"DC01"},' \
          '{"text":"of-db01","type":"HOSTNAME"}]}'
    assert llm_detector._parse_entities(raw, "connect to of-db01 (DC01)") == [("of-db01", "HOSTNAME")]


def test_wellformed_but_unusable_entity_is_skipped_not_raised():
    # Correct shape, but the text isn't in the input / type we don't anonymize:
    # that's benign variance, not a malfunction — skip without raising.
    raw = '{"entities":[{"text":"not-in-input","type":"HOSTNAME"},' \
          '{"text":"of-db01","type":"WEATHER"}]}'
    assert llm_detector._parse_entities(raw, "connect to of-db01 now") == []
