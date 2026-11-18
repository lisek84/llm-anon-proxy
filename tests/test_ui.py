"""Live dashboard: event bus, masking, and routes (not swallowed by catch-all)."""
import os
import tempfile
from pathlib import Path

import httpx
import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-ui-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write("keywords:\n  - example\n")

from anonproxy import events, webui, vault, dictionary  # noqa: E402
from anonproxy.config import config  # noqa: E402
from anonproxy.main import app  # noqa: E402

_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "uitest"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.UI_ENABLED = True
    config.UI_SHOW_ORIGINALS = False
    vault.init()
    dictionary.load()
    yield


def test_event_bus_since_and_snapshot():
    events.emit_catch("tool_result", "DOMAIN", "secret-host.example", "fake.example")
    snap = events.snapshot()
    assert snap["last_id"] > 0
    assert any(e.get("type") == "DOMAIN" for e in snap["recent"])
    assert events.since(snap["last_id"]) == []  # nothing newer yet


def test_uiauth_states_and_fail_closed(tmp_path, monkeypatch):
    from anonproxy import uiauth
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    # no file → open
    assert uiauth._state()[0] == "open" and not uiauth.required()
    # a configured viewer → login required, file is valid JSON and 0600
    uiauth.add_user("alice", "hunter2hunter")
    assert uiauth._state()[0] == "auth" and uiauth.required()
    import json as _json
    assert "alice" in _json.loads((tmp_path / "ui-users.json").read_text())
    # corrupt file → 'error' and STILL required (must not fall open)
    (tmp_path / "ui-users.json").write_text("{ this is not json")
    assert uiauth._state()[0] == "error" and uiauth.required()


def test_uiauth_corrupt_file_returns_503(tmp_path, monkeypatch):
    from anonproxy import uiauth
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    (tmp_path / "ui-users.json").write_text("not valid json {{")

    class _Req:
        headers: dict = {}
    resp = uiauth.challenge_if_needed(_Req())
    assert resp is not None and resp.status_code == 503   # fail closed, not open


def test_serialize_masks_by_default():
    e = {"id": 1, "kind": "catch", "ts": 0, "source": "message",
         "type": "DOMAIN", "original": "secret-host.example", "surrogate": "fake.example"}
    config.UI_SHOW_ORIGINALS = False
    masked = webui._serialize(e)
    assert masked["original"] != "secret-host.example"
    assert masked["surrogate"] == "fake.example"       # surrogate never masked
    config.UI_SHOW_ORIGINALS = True
    shown = webui._serialize(e)
    assert shown["original"] == "secret-host.example"


@pytest.mark.asyncio
async def test_ui_routes_served_not_forwarded():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as c:
        page = await c.get("/ui")
        assert page.status_code == 200 and "llm-anon-proxy" in page.text
        stats = await c.get("/ui/stats")
        assert stats.status_code == 200
        body = stats.json()
        assert "stats" in body and "recent" in body and body["show_originals"] is False
