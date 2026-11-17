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


# ── TLS cert resolution ───────────────────────────────────────────────────────

def test_tls_off_returns_none():
    from anonproxy import tls
    config.TLS = False
    config.TLS_CERT = config.TLS_KEY = ""
    assert tls.resolve() == (None, None)


def test_tls_self_signed_generated(tmp_path):
    import stat as _stat
    from anonproxy import tls
    config.TLS = True
    config.TLS_CERT = config.TLS_KEY = ""
    config.DATA_DIR = tmp_path
    config.TLS_SAN = "proxy.test,10.0.0.9"
    cert, key = tls.resolve()
    assert os.path.exists(cert) and os.path.exists(key)
    assert _stat.S_IMODE(os.stat(key).st_mode) == 0o600
    data = open(cert, "rb").read()
    assert b"BEGIN CERTIFICATE" in data
    # reused on next call (no regeneration)
    assert tls.resolve() == (cert, key)
    config.TLS = False
    config.DATA_DIR = Path(_MY_DB).parent


def test_tls_explicit_cert_paths_passthrough():
    from anonproxy import tls
    config.TLS = False
    config.TLS_CERT = "/x/c.pem"
    config.TLS_KEY = "/x/k.pem"
    assert tls.resolve() == ("/x/c.pem", "/x/k.pem")
    config.TLS_CERT = config.TLS_KEY = ""


# ── Review #4: audit path hardened, header token, input_schema anonymized ─────

def test_audit_path_in_sensitive_and_hardened(tmp_path):
    import stat as _stat
    from anonproxy import preflight
    config.DATA_DIR = tmp_path
    config.AUDIT_PATH = tmp_path / "audit.log.jsonl"
    config.DB_PATH = tmp_path / "t.db"
    config.SECRET_KEY_PATH = tmp_path / "secret.key"
    config.DICT_PATH = tmp_path / "dict.yaml"
    config.LEAKLOG_PATH = tmp_path / "rotate.jsonl"
    assert config.AUDIT_PATH in preflight._sensitive_paths()
    config.AUDIT_PATH.write_text("x")
    os.chmod(config.AUDIT_PATH, 0o644)
    preflight.harden_permissions()
    assert _stat.S_IMODE(os.stat(config.AUDIT_PATH).st_mode) == 0o600
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)


@pytest.mark.asyncio
async def test_token_via_header():
    config.TOKEN = "hdr123"
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://p") as c:
        assert (await c.get("/ui/stats")).status_code == 403
        r = await c.get("/ui/stats", headers={"x-anonproxy-token": "hdr123"})
        assert r.status_code == 200
    config.TOKEN = ""


@pytest.mark.asyncio
async def test_tool_input_schema_description_anonymized():
    body = {"model": "m", "messages": [],
            "tools": [{"name": "run", "description": "ok",
                       "input_schema": {"type": "object", "properties": {
                           "host": {"type": "string",
                                    "description": "default example.com box"}}}}]}
    out = await main._anon_body(body)
    desc = out["tools"][0]["input_schema"]["properties"]["host"]["description"]
    assert "example.com" not in desc
    # structure preserved
    assert out["tools"][0]["input_schema"]["properties"]["host"]["type"] == "string"


# ── Dashboard login (optional HTTP Basic) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_ui_open_by_default_then_requires_login(tmp_path):
    import base64 as _b64
    from anonproxy import uiauth
    config.DATA_DIR = tmp_path
    config.UI_ENABLED = True
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://p") as c:
        assert (await c.get("/ui/stats")).status_code == 200      # open by default
        uiauth.add_user("alice", "sekret12")                      # enables login
        assert (await c.get("/ui/stats")).status_code == 401      # now required
        cred = _b64.b64encode(b"alice:sekret12").decode()
        r = await c.get("/ui/stats", headers={"authorization": f"Basic {cred}"})
        assert r.status_code == 200
        bad = _b64.b64encode(b"alice:wrong").decode()
        assert (await c.get("/ui/stats",
                            headers={"authorization": f"Basic {bad}"})).status_code == 401
        uiauth.disable()
        assert (await c.get("/ui/stats")).status_code == 200      # open again
    config.DATA_DIR = Path(_MY_DB).parent


@pytest.mark.asyncio
async def test_llm_bad_json_is_unavailable(monkeypatch):
    config.LLM_ENABLED = True

    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"message": {"content": "not json at all {{"}}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    monkeypatch.setattr(llm_detector.httpx, "AsyncClient", _Client)
    with pytest.raises(llm_detector.LLMUnavailable):
        await llm_detector.detect("text with an entity DC01 here")


@pytest.mark.asyncio
async def test_unscannable_block_emits_dashboard_notice():
    from anonproxy import events
    config.BLOCK_UNSCANNABLE = False
    before = events.snapshot()["notices"]
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": "x"}}]}]}
    await main._anon_body(body)
    assert events.snapshot()["notices"] > before
