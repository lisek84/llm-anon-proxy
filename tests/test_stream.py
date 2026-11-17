"""Streaming restore: tool_use JSON safety (B1) and non-tool_use blocks (B2)."""
import json
import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-stream-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")

from anonproxy import main, vault, surrogates  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.path.join(_TMP, "t.db")


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "streamtest"
    config.DB_PATH = Path(_MY_DB)
    config.AUDIT_ENABLED = False
    vault.init()
    yield


def test_deanon_tool_json_keeps_valid_json_with_special_chars():
    # A restored value with a quote, backslash and newline must stay valid JSON.
    secret = 'line1\n"quote"\\back'
    vault.get_or_create(secret, "CREDENTIAL", lambda o, e, a: "[CRED_TESTAAA1]")
    restored, _ = main._deanon_tool_json('{"command": "use [CRED_TESTAAA1] here"}')
    obj = json.loads(restored)   # must parse
    assert obj["command"] == "use " + secret + " here"


class _FakeResp:
    status_code = 200

    def __init__(self, sse: str):
        self._sse = sse

    async def aiter_lines(self):
        for ln in self._sse.split("\n"):
            yield ln

    async def aclose(self):
        pass


class _FakeClient:
    async def aclose(self):
        pass


def _sse_events(events):
    return "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events)


@pytest.mark.asyncio
async def test_server_tool_use_input_is_emitted_and_restored():
    sur, _ = vault.get_or_create("10.1.2.3", "IP_ADDRESS", surrogates.generate)
    tj = json.dumps({"query": f"status of {sur}"})
    events = [
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "server_tool_use", "id": "s1",
                                                   "name": "web_search", "input": {}}}),
    ]
    for i in range(0, len(tj), 7):
        events.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                       "delta": {"type": "input_json_delta", "partial_json": tj[i:i + 7]}}))
    events.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
    events.append(("message_stop", {"type": "message_stop"}))

    out = ""
    async for chunk in main._stream_and_deanon(_FakeResp(_sse_events(events)), _FakeClient(), "m"):
        out += chunk

    # Reconstruct the tool input JSON from the emitted deltas.
    tool_json = ""
    for line in out.splitlines():
        if line.startswith("data:"):
            evt = json.loads(line[5:].strip())
            if evt.get("type") == "content_block_delta" and evt["delta"].get("type") == "input_json_delta":
                tool_json += evt["delta"]["partial_json"]
    assert tool_json, "server_tool_use input was dropped"
    assert json.loads(tool_json)["query"] == "status of 10.1.2.3"


def test_deanon_tool_json_restores_keys():
    # Streaming tool_use must restore surrogate KEYS too (symmetric with anonymize_value).
    vault.get_or_create("secret-host.internal", "HOSTNAME", lambda o, e, a: "host-zzz999")
    restored, _ = main._deanon_tool_json('{"host-zzz999": "up"}')
    assert json.loads(restored) == {"secret-host.internal": "up"}
