"""
Adversarial / behavioural suite (proposed in an external review). No live API.

Checks, end to end through _anon_body / the stream generator:
  * a declared secret cannot ride out via ANY block type or tool field (keys too);
  * benign tech terms are NOT over-anonymized;
  * encodings of a declared value are caught;
  * streaming never emits an un-restored surrogate and restores keys;
  * unknown block types are reported (visibility), infra failures don't crash.
"""
import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-adv-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write(
        "domains:\n  - secretcorp.com\n"
        "hosts:\n  - prod-db-01\n"
        "ips:\n  - 203.0.11.77\n"
        "keywords:\n  - secretcorp\n"
        "usernames:\n  - svc_deploy\n"
        "paths:\n  - /srv/secretcorp\n"
    )

from anonproxy import main, vault, dictionary, llm_detector, leaklog  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]
SECRETS = ["secretcorp.com", "prod-db-01", "203.0.11.77", "svc_deploy", "/srv/secretcorp"]


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "adv"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.AUDIT_ENABLED = False
    config.LLM_ENABLED = False
    config.BLOCK_UNSCANNABLE = False
    config.BLOCK_UNKNOWN_ENDPOINTS = False
    vault.init()
    dictionary.load()
    yield


@pytest.mark.asyncio
async def test_no_secret_escapes_any_block_or_tool_field():
    body = {
        "model": "m",
        "system": "cwd /srv/secretcorp",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "ssh svc_deploy@prod-db-01 (203.0.11.77)"},
                {"type": "tool_use", "id": "t1", "name": "bash",
                 "input": {"cmd": "psql -h secretcorp.com",
                           "prod-db-01": "the real host"}},            # secret as a KEY
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": "connected to 203.0.11.77 as svc_deploy"},
                {"type": "document", "source": {"type": "text", "media_type": "text/plain",
                                                "data": "host prod-db-01 at secretcorp.com"}},
                {"type": "search_result", "content": [
                    {"type": "text", "text": "see https://secretcorp.com/admin"}]},
            ]},
        ],
        "tools": [{"name": "deploy", "description": "pushes to secretcorp.com",
                   "input_schema": {"type": "object", "properties": {
                       "target": {"type": "string", "description": "e.g. prod-db-01 / 203.0.11.77"}}}}],
    }
    out = await main._anon_body(body)
    blob = json.dumps(out)
    for s in SECRETS:
        assert s not in blob, f"LEAK: {s!r} survived in outgoing body"


@pytest.mark.parametrize("term", [
    "PostgreSQL 18", "Ubuntu 24.04", "kubectl", "nginx", "OpenSSH 9.6",
    "CVE-2024-6387", "port 5432", "/etc/passwd", "git", "systemctl status",
    "README.md", "deploy.sh", "user.id",
])
def test_benign_tech_terms_not_over_anonymized(term):
    from anonproxy import anonymizer
    assert term in anonymizer.anonymize(f"context: {term} here", source="t")


def test_encoded_forms_of_declared_value_caught():
    import base64
    from anonproxy import anonymizer
    for enc in (base64.b64encode(b"secretcorp.com").decode(),
                b"secretcorp.com".hex(),
                base64.b32encode(b"secretcorp.com").decode()):
        anon = anonymizer.anonymize(f"blob {enc}", source="t")
        assert enc not in anon


@pytest.mark.asyncio
async def test_unknown_block_type_is_reported():
    from anonproxy import events
    before = events.snapshot()["notices"]
    await main._anon_body({"model": "m", "messages": [
        {"role": "user", "content": [{"type": "video", "source": {"data": "x"}}]}]})
    assert events.snapshot()["notices"] > before


def test_leaklog_failure_does_not_raise(monkeypatch):
    # Simulate a write failure; record() must swallow it.
    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr("builtins.open", _boom)
    leaklog._seen_hashes.clear()
    leaklog.record("AKIA" + "IOSFODNN7EXAMPLE", "TOKEN", "leaked", "t")  # no raise


@pytest.mark.asyncio
async def test_streaming_never_emits_unrestored_surrogate():
    from tests.test_stream import _FakeResp, _FakeClient, _sse_events  # reuse helpers
    from anonproxy import surrogates
    sur, _ = vault.get_or_create("203.0.11.77", "IP_ADDRESS", surrogates.generate)
    events_sse = [("content_block_start", {"type": "content_block_start", "index": 0,
                   "content_block": {"type": "text", "text": ""}})]
    for piece in ["connect ", *list(sur), " done"]:   # surrogate split char by char
        events_sse.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                           "delta": {"type": "text_delta", "text": piece}}))
    events_sse.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
    events_sse.append(("message_stop", {"type": "message_stop"}))
    out = ""
    async for ch in main._stream_and_deanon(_FakeResp(_sse_events(events_sse)), _FakeClient(), "m"):
        out += ch
    text = ""
    for line in out.splitlines():
        if line.startswith("data:"):
            evt = json.loads(line[5:].strip())
            if evt.get("type") == "content_block_delta" and evt["delta"].get("type") == "text_delta":
                text += evt["delta"]["text"]
    assert text == "connect 203.0.11.77 done"       # restored whole
    assert sur not in text                            # no surrogate left behind
