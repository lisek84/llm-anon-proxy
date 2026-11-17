"""
End-to-end proxy test against a fake upstream (no real API, no network egress).

Verifies:
  * the body forwarded upstream contains surrogates, never the real secrets,
    across the full history including assistant tool_use;
  * the streamed response is deanonymized back to real values, even when a
    surrogate is split across many 1-char SSE deltas and inside tool_use JSON.
"""
import json
import os
import socket
import tempfile
import threading
import time

import httpx
import pytest
import uvicorn

# ── Pick a free port and configure BEFORE importing the app ───────────────────
_sock = socket.socket()
_sock.bind(("127.0.0.1", 0))
_UP_PORT = _sock.getsockname()[1]
_sock.close()

_TMP = tempfile.mkdtemp(prefix="anonproxy-proxytest-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
os.environ["ANONPROXY_LEAKLOG"] = os.path.join(_TMP, "rotate.jsonl")
os.environ["ANONPROXY_CONTEXT"] = "proxytest"
os.environ["ANONPROXY_UPSTREAM"] = f"http://127.0.0.1:{_UP_PORT}"
os.environ["ANONPROXY_LLM"] = "false"

with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write("domains:\n  - example.com\nhosts:\n  - of-prod-db01\nips:\n  - 185.12.34.56\n")

from anonproxy import vault, dictionary, anonymizer, surrogates  # noqa: E402
from anonproxy.config import config  # noqa: E402
from anonproxy.main import app  # noqa: E402

# The config singleton may have been created by another test module first, so
# set the values this test relies on explicitly (mirrors the app's startup).
# Capture this module's own paths now — env vars are shared across test modules.
_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]

# ── Fake upstream ─────────────────────────────────────────────────────────────
_received = {}


async def _fake_upstream(scope, receive, send):
    assert scope["type"] == "http"
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    _received["body"] = body.decode("utf-8")
    _received["query"] = scope.get("query_string", b"").decode("utf-8")

    # Build a surrogate the proxy must restore. The real IP is in the dictionary;
    # anonymize it the same way the proxy would.
    sur_ip, _ = vault.get_or_create("185.12.34.56", "IP_ADDRESS", surrogates.generate)

    events = []
    events.append(("message_start", {"type": "message_start",
                   "message": {"id": "m1", "type": "message", "role": "assistant",
                               "content": [], "model": "x", "usage": {}}}))
    events.append(("content_block_start", {"type": "content_block_start", "index": 0,
                   "content_block": {"type": "text", "text": ""}}))
    # Emit "ssh root@<surrogate> now" with the surrogate split char-by-char.
    for piece in ["ssh ", "root@"] + list(sur_ip) + [" now"]:
        events.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                       "delta": {"type": "text_delta", "text": piece}}))
    events.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
    # A tool_use whose input references the surrogate inside JSON.
    events.append(("content_block_start", {"type": "content_block_start", "index": 1,
                   "content_block": {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}}))
    tj = json.dumps({"command": f"ping {sur_ip}"})
    for i in range(0, len(tj), 5):
        events.append(("content_block_delta", {"type": "content_block_delta", "index": 1,
                       "delta": {"type": "input_json_delta", "partial_json": tj[i:i + 5]}}))
    events.append(("content_block_stop", {"type": "content_block_stop", "index": 1}))
    events.append(("message_delta", {"type": "message_delta",
                   "delta": {"stop_reason": "tool_use"}, "usage": {}}))
    events.append(("message_stop", {"type": "message_stop"}))

    payload = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events)
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/event-stream")]})
    await send({"type": "http.response.body", "body": payload.encode()})


@pytest.fixture(autouse=True)
def _ctx():
    from pathlib import Path
    config.UPSTREAM_URL = f"http://127.0.0.1:{_UP_PORT}"
    config.CONTEXT_ID = "proxytest"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.LLM_ENABLED = False
    config.AUDIT_ENABLED = False
    vault.init()
    dictionary.load()
    yield


@pytest.fixture(scope="module", autouse=True)
def _upstream_server():
    cfg = uvicorn.Config(_fake_upstream, host="127.0.0.1", port=_UP_PORT, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield
    server.should_exit = True
    t.join(timeout=5)


@pytest.mark.asyncio
async def test_request_anonymized_and_response_restored():
    req_body = {
        "model": "claude-opus-4-8", "stream": True, "max_tokens": 1024,
        "system": "cwd is /x",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "zaloguj sie na of-prod-db01 (185.12.34.56) dla example.com"}]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "p1", "name": "Bash",
                 "input": {"command": "ssh root@185.12.34.56 # of-prod-db01"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "p1", "content": "app at example.com up"}]},
        ],
    }
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        async with client.stream("POST", "/v1/messages", json=req_body) as resp:
            chunks = [c async for c in resp.aiter_text()]
    raw = "".join(chunks)

    # Reconstruct text and tool_use JSON from the SSE deltas.
    text, tool_json = "", ""
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        evt = json.loads(line[len("data:"):].strip())
        if evt.get("type") == "content_block_delta":
            d = evt["delta"]
            if d.get("type") == "text_delta":
                text += d.get("text", "")
            elif d.get("type") == "input_json_delta":
                tool_json += d.get("partial_json", "")

    # 1) Upstream never saw the real secrets.
    sent = _received["body"]
    for secret in ("185.12.34.56", "of-prod-db01", "example.com"):
        assert secret not in sent, f"LEAK upstream: {secret}"
    assert "198.1" in sent  # surrogate IP shape present

    # 2) The streamed response restored the real IP, in text and in tool_use JSON.
    assert text == "ssh root@185.12.34.56 now", repr(text)
    assert json.loads(tool_json)["command"] == "ping 185.12.34.56", repr(tool_json)


@pytest.mark.asyncio
async def test_document_text_and_tool_description_anonymized():
    # A3: document(source.type=text).data and tools[].description are scrubbed.
    body = {
        "model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "document",
                 "source": {"type": "text", "media_type": "text/plain",
                            "data": "host of-prod-db01 at 185.12.34.56"}}]}],
        "tools": [{"name": "deploy", "description": "pushes to example.com prod",
                   "input_schema": {"type": "object"}}],
    }
    from anonproxy import main
    out = await main._anon_body(body)
    doc = out["messages"][0]["content"][0]["source"]["data"]
    assert "of-prod-db01" not in doc and "185.12.34.56" not in doc
    assert "example.com" not in out["tools"][0]["description"]


@pytest.mark.asyncio
async def test_passthrough_bodyless_get_emits_notice_and_scans_query():
    # An unknown endpoint hit with GET (no body) but a secret in the query must
    # still raise a dashboard notice and be scanned — not silently forwarded.
    from anonproxy import events
    ghp = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
    before = events.snapshot()["notices"]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        await client.get(f"/some/endpoint?token={ghp}")
    after = events.snapshot()["notices"]
    assert after > before, "no un-anonymized notice for a body-less GET passthrough"


@pytest.mark.asyncio
async def test_passthrough_preserves_repeated_query_keys():
    # ?tag=a&tag=b must reach upstream as two params, not collapsed to one.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        await client.get("/api?tag=production&tag=database")
    from urllib.parse import parse_qsl
    pairs = parse_qsl(_received["query"])
    assert ("tag", "production") in pairs and ("tag", "database") in pairs
    assert [v for k, v in pairs if k == "tag"] == ["production", "database"]


@pytest.mark.asyncio
async def test_passthrough_scans_urlencoded_query(monkeypatch):
    # A percent-encoded secret (?token=ghp%5F…) has no literal "ghp_" in the raw
    # query, but upstream receives it decoded — the scanner must see the decoded
    # value, not just the raw string.
    from anonproxy import anonymizer
    seen = []
    monkeypatch.setattr(anonymizer, "scan_for_leaks",
                        lambda text, source="x": (seen.append(text), 0)[1])
    ghp = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
    enc = "ghp%5F" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"   # underscore encoded
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        await client.get(f"/some/thing?token={enc}")
    assert any(ghp in t for t in seen), "decoded query secret never reached the scanner"


@pytest.mark.asyncio
async def test_inline_tool_addition_block_anonymized():
    # inline-tools beta: a tool declared inside a message as a `tool_addition`
    # block must have its free-text fields scrubbed too (not forwarded as-is),
    # while the tool name and schema structure stay intact so calls resolve.
    body = {
        "model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "tool_addition",
                 "tool": {
                     "type": "tool_definition",
                     "name": "ssh_run",
                     "description": "run a command on of-prod-db01 (185.12.34.56)",
                     "input_schema": {
                         "type": "object",
                         "properties": {
                             "host": {"type": "string",
                                      "description": "target like example.com"}},
                         "required": ["host"]}}}]}],
    }
    from anonproxy import main
    out = await main._anon_body(body)
    tool = out["messages"][0]["content"][0]["tool"]
    assert tool["name"] == "ssh_run"                      # name untouched
    assert tool["input_schema"]["required"] == ["host"]   # structure untouched
    assert "of-prod-db01" not in tool["description"]
    assert "185.12.34.56" not in tool["description"]
    assert "example.com" not in tool["input_schema"]["properties"]["host"]["description"]
