"""Fail-closed options and the optional path token (from the external review)."""
import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-sec-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write("domains:\n  - example.com\n")

from anonproxy import main, vault, dictionary, llm_detector  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "sectest"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.AUDIT_ENABLED = False
    config.LLM_ENABLED = False
    config.BLOCK_UNSCANNABLE = False
    config.BLOCK_UNKNOWN_ENDPOINTS = False
    config.TOKEN = ""
    vault.init()
    dictionary.load()
    yield


# ── P1: block unscannable content ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_block_unscannable_raises_when_enabled():
    config.BLOCK_UNSCANNABLE = True
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": "…"}}]}]}
    with pytest.raises(main.UnscannableContent):
        await main._anon_body(body)


@pytest.mark.asyncio
async def test_unscannable_warns_but_passes_by_default():
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": "…"}}]}]}
    out = await main._anon_body(body)  # no raise
    assert out["messages"][0]["content"][0]["type"] == "image"


# ── P2 / P6: HTTP-level, no upstream needed (blocked before forwarding) ────────

@pytest.mark.asyncio
async def test_block_unknown_endpoint():
    config.BLOCK_UNKNOWN_ENDPOINTS = True
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://p") as c:
        r = await c.get("/v1/models")
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_token_required_when_set():
    config.TOKEN = "s3cr3t"
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://p") as c:
        assert (await c.get("/health")).status_code == 200          # always open
        assert (await c.get("/ui/stats")).status_code == 403         # missing token
        assert (await c.get("/s3cr3t/ui/stats")).status_code == 200  # with token


# ── P3: every Ollama HTTP error is LLMUnavailable (fail-closed holds) ──────────

@pytest.mark.asyncio
async def test_llm_http_error_is_unavailable(monkeypatch):
    config.LLM_ENABLED = True

    class _Resp:
        status_code = 500

        def raise_for_status(self):
            raise httpx.HTTPStatusError("500", request=None, response=None)

        def json(self):
            return {}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    monkeypatch.setattr(llm_detector.httpx, "AsyncClient", _Client)
    with pytest.raises(llm_detector.LLMUnavailable):
        await llm_detector.detect("some text with an entity DC01 here")
