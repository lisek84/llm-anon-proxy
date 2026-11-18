"""
Local anonymization proxy for Claude Code.

    export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
    claude

Every request body (system prompt, full message history, tool_use inputs and
tool_result outputs) is anonymized before leaving the machine. Responses —
including streamed text and tool_use arguments — are restored to real values
before Claude Code sees them, so commands run against real hosts.
"""
import json
import logging
import os
import time

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from starlette.middleware.base import BaseHTTPMiddleware

from . import (anonymizer, dictionary, events, leaklog, llm_detector, preflight,
               regex_detector, uiauth, vault, webui)
from .config import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("anonproxy")

app = FastAPI(title="anonproxy")


class _TokenMiddleware(BaseHTTPMiddleware):
    """If ANONPROXY_TOKEN is set, require it as a URL path prefix
    (ANTHROPIC_BASE_URL=http://host:8787/<token>) and strip it before routing.
    /health is always open. For non-loopback deployments."""

    async def dispatch(self, request: Request, call_next):
        token = config.TOKEN
        if not token or request.url.path == "/health":
            return await call_next(request)
        # Preferred: a header (does not land in URL/access logs). Clients that
        # can only set ANTHROPIC_BASE_URL (Claude Code) use the path prefix.
        if request.headers.get("x-anonproxy-token") == token:
            return await call_next(request)
        prefix = f"/{token}"
        path = request.url.path
        if path == prefix or path.startswith(prefix + "/"):
            stripped = path[len(prefix):] or "/"
            request.scope["path"] = stripped
            request.scope["raw_path"] = stripped.encode()
            return await call_next(request)
        return Response(content=json.dumps({"type": "error", "error": {
            "type": "forbidden", "message": "missing or wrong proxy token"}}),
            status_code=403, media_type="application/json")


app.add_middleware(_TokenMiddleware)

# RFC 7230 hop-by-hop headers (+ proxy auth, which is strictly between hops and
# must never be forwarded) + our own auth header. Headers NAMED in a request's
# `Connection` value are also hop-by-hop and are stripped dynamically below.
_HOP_BY_HOP = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding",
               "keep-alive", "te", "trailer", "upgrade", "proxy-connection",
               "proxy-authenticate", "proxy-authorization",
               "x-anonproxy-token"}  # our own auth header must never reach Anthropic


@app.on_event("startup")
async def _startup() -> None:
    # Isolation preflight first: in 'enforce' mode this raises and the server
    # does not come up if the agent could read the de-anonymization data.
    preflight.run()
    vault.init()
    dictionary.load()
    # Fail fast and clearly if the secret key / data dir isn't ours: otherwise the
    # first request that needs a surrogate dies with a 500 mid-flight. Common when
    # the data dir was chowned to the proxy's UID but a pre-existing secret.key /
    # mappings.db inside it was left owned by another user.
    try:
        import anonproxy.surrogates as _surr
        _surr._load_secret()
    except OSError as exc:
        log.error("cannot access the secret key at %s: %s", config.SECRET_KEY_PATH, exc)
        log.error("the data dir AND everything in it must be owned+readable by this "
                  "process's user (uid=%d). Fix: chown -R %d:%d '%s'",
                  os.getuid(), os.getuid(), os.getgid(), config.DATA_DIR)
        raise RuntimeError(f"secret key not accessible: {exc}") from exc
    log.info("context=%s upstream=%s llm=%s db=%s",
             config.CONTEXT_ID, config.UPSTREAM_URL, config.LLM_ENABLED, config.DB_PATH)
    log.info("dictionary entries loaded; listening on %s:%s", config.HOST, config.PORT)


# Headers Anthropic/the SDK legitimately need — not flagged as "unrecognized".
# (Authorization / x-api-key are the provider secret and must pass through.)
_REQUIRED_HEADERS = {
    "authorization", "x-api-key", "content-type", "accept", "accept-language",
    "anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access",
    "user-agent", "x-api-version", "x-app",   # x-app: Claude Code's own client tag
    # standard browser headers (a browser hitting the port shouldn't raise alarms)
    "accept-encoding", "cache-control", "pragma", "dnt", "priority", "referer",
    "origin", "upgrade-insecure-requests", "connection", "content-length",
}
_KNOWN_HEADER_PREFIXES = ("x-stainless-", "anthropic-", "sec-", "x-anonproxy-",
                          "x-claude-code-")   # session id etc. — Claude Code's own
_warned_headers: set[str] = set()


def _scan_forward_headers(forwarded: dict[str, str]) -> None:
    """Headers bypass body anonymization, so at least SCAN their values for leaks
    and flag any unrecognized header once on the dashboard. We don't rewrite them
    (that would break auth), but the user must know if a client sends real data
    (Cookie, X-Internal-User, …) in a header."""
    for k, v in forwarded.items():
        kl = k.lower()
        if kl in ("authorization", "x-api-key"):
            continue  # the required provider secret — expected, scanning is noise
        try:
            anonymizer.scan_for_leaks(v, f"header:{kl}")
        except Exception:  # noqa: BLE001
            pass
        if kl not in _REQUIRED_HEADERS and not kl.startswith(_KNOWN_HEADER_PREFIXES) \
                and kl not in _warned_headers:
            _warned_headers.add(kl)
            events.emit_notice(f"forwarding unrecognized header '{kl}' un-anonymized", "header")


def _redact_for_display(s: str) -> str:
    """Redact secret-shaped substrings before showing a fail-open path on the
    dashboard — an un-anonymized path must not be exposed verbatim to viewers.
    Covers regex-detected secrets AND user dictionary values (a client/project
    name in the path must not surface), over both the raw and URL-decoded form."""
    try:
        from urllib.parse import unquote
        decoded = unquote(s)
        matches = {v for v, _ in regex_detector.detect(s)} | {v for v, _ in dictionary.detect(s)}
        dec_matches = ({v for v, _ in regex_detector.detect(decoded)}
                       | {v for v, _ in dictionary.detect(decoded)}) if decoded != s else set()
        out = s
        for val in matches | dec_matches:
            if len(val) >= 4 and val in out:
                out = out.replace(val, val[:2] + "…" + val[-2:])
        # A secret visible only once URL-decoded (…?x=klient%2Dalfa) would still be
        # in the raw string in encoded form — redact the whole path to be safe.
        if any(len(v) >= 4 and v not in out for v in dec_matches):
            return "[redacted: encoded value]"
        return out
    except Exception:  # noqa: BLE001
        return "[redacted]"


def _fwd_headers(request: Request) -> dict[str, str]:
    # Also drop any header token listed in the client's `Connection` value (those
    # are per-hop and must not be forwarded to Anthropic).
    drop = set(_HOP_BY_HOP)
    for tok in request.headers.get("connection", "").split(","):
        tok = tok.strip().lower()
        if tok:
            drop.add(tok)
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in drop}
    _scan_forward_headers(fwd)
    return fwd


# Upstream response headers worth passing back to Claude Code (request-id,
# anthropic-ratelimit-*, retry-after …). Drop hop-by-hop and length/encoding —
# we re-serialize or re-chunk the body, so the originals no longer apply.
_RESP_DROP = {"content-length", "content-encoding", "transfer-encoding",
              "connection", "keep-alive", "content-type"}


def _resp_headers(resp: httpx.Response) -> dict[str, str]:
    return {k: v for k, v in resp.headers.items() if k.lower() not in _RESP_DROP}


# ── Request anonymization ─────────────────────────────────────────────────────

async def _llm(text: str) -> list[tuple[str, str]]:
    if not config.LLM_ENABLED:
        return []
    try:
        return await llm_detector.detect(text)
    except llm_detector.LLMUnavailable:
        # Fail-closed: propagate so the whole request is blocked (never forwarded
        # half-anonymized). Otherwise degrade to dictionary+regex for every
        # string uniformly — no partial state.
        if config.LLM_FAIL_CLOSED:
            raise
        # Fail-open must be VISIBLE: detection quality just dropped. Surface it on
        # the dashboard (throttled so one request's many strings don't spam).
        global _last_llm_degrade_notice
        now = time.monotonic()
        if now - _last_llm_degrade_notice > 2.0:
            _last_llm_degrade_notice = now
            events.emit_notice("LLM detector unavailable — processed with dictionary+regex only",
                               "llm")
        log.warning("LLM layer unavailable — degrading to dictionary+regex for this request")
        return []


_last_llm_degrade_notice = 0.0

# The contextual LLM layer runs only on the user's prose (messages + tool_result
# content), NOT on Claude Code's own system prompt or tool schemas: a small model
# floods that boilerplate with false-positive ORGANIZATION hits — garbling
# Claude's instructions, costing an Ollama call per block, and slowing every
# request. The deterministic dict+regex layers still run on system/tools and
# catch any real IPs/domains/hosts/secrets injected there (e.g. cwd, env).
_LLM_SKIP_SOURCES = {"system", "tools"}


async def _anon_text(text: str, source: str) -> str:
    matches = [] if source in _LLM_SKIP_SOURCES else await _llm(text)
    return anonymizer.anonymize(text, llm_matches=matches, source=source)


_warned_block_types: set[str] = set()


class UnscannableContent(Exception):
    """Raised for a block the proxy can't scrub when BLOCK_UNSCANNABLE is on."""


def _warn_unanonymized(kind: str, source: str = "message") -> None:
    if config.BLOCK_UNSCANNABLE:
        raise UnscannableContent(kind)
    # Every occurrence is surfaced on the dashboard (the whole point: the user
    # must know data left un-anonymized); the log warns once per type to stay quiet.
    events.emit_notice(f"forwarded un-anonymized {kind} block", source)
    if kind not in _warned_block_types:
        _warned_block_types.add(kind)
        log.warning("'%s' blocks are NOT anonymized — their payload is forwarded "
                    "as-is (dashboard shows every occurrence)", kind)


async def _anon_block(block: dict, source: str) -> dict:
    t = block.get("type")
    if t == "text" and isinstance(block.get("text"), str):
        block["text"] = await _anon_text(block["text"], source)
    elif t == "thinking":
        # Pass through unchanged, both directions: the model only ever saw
        # surrogates, so thinking carries no real data, and altering it would
        # break the block's signature (the API rejects a mismatched thinking).
        pass
    elif t in ("tool_use", "mcp_tool_use"):
        # mcp_tool_use is a remote-MCP tool call; its input is user data heading
        # upstream, so anonymize it exactly like a normal tool_use input.
        inp = block.get("input", {})
        matches = [] if source in _LLM_SKIP_SOURCES else await _llm(json.dumps(inp))
        block["input"] = anonymizer.anonymize_value(inp, matches, source)
    elif t in ("tool_result", "mcp_tool_result"):
        c = block.get("content")
        if isinstance(c, str):
            block["content"] = await _anon_text(c, source)
        elif isinstance(c, list):
            block["content"] = [await _anon_block(b, source) for b in c]
    elif t == "mcp_tool_listing":
        # A listing of a remote MCP server's tools (names + free-text descriptions
        # + input schemas). Scrub the free-text fields like any tool definition.
        await _anon_schema_text(block)
    elif t == "document":
        src = block.get("source")
        if isinstance(src, dict) and src.get("type") == "text" and isinstance(src.get("data"), str):
            src["data"] = await _anon_text(src["data"], source)
        else:
            _warn_unanonymized("document")  # base64 PDF/image payloads can't be scrubbed
    elif t == "search_result":
        c = block.get("content")
        if isinstance(c, list):
            block["content"] = [await _anon_block(b, source) for b in c]
    elif t == "tool_addition":
        # Inline tool definition (inline-tools beta: a tool declared in a message
        # instead of the top-level `tools` array). Treat it exactly like a
        # top-level tool def — anonymize only free-text description/title fields,
        # leaving tool names and JSON-Schema structure intact so calls resolve.
        await _anon_schema_text(block)
    elif t == "image":
        _warn_unanonymized("image")  # screenshots may contain real data
    elif t is not None:
        _warn_unanonymized(t)
    return block


async def _anon_message(msg: dict) -> dict:
    c = msg.get("content")
    if isinstance(c, str):
        msg["content"] = await _anon_text(c, "message")
    elif isinstance(c, list):
        msg["content"] = [await _anon_block(b, "message") for b in c]
    return msg


async def _anon_body(body: dict) -> dict:
    sys_p = body.get("system")
    if isinstance(sys_p, str):
        body["system"] = await _anon_text(sys_p, "system")
    elif isinstance(sys_p, list):
        body["system"] = [await _anon_block(b, "system") for b in sys_p]
    if isinstance(body.get("messages"), list):
        body["messages"] = [await _anon_message(m) for m in body["messages"]]
    # Tool definitions (esp. MCP) can embed real values in free-text fields —
    # the top-level description and, nested in input_schema, property
    # descriptions/titles. Only those free-text fields are anonymized; the JSON
    # Schema structure (type, property names, required…) is left intact.
    if isinstance(body.get("tools"), list):
        for tool in body["tools"]:
            await _anon_schema_text(tool)
    # Remote MCP connector: Anthropic connects to the server itself, so it needs
    # the REAL url + authorization_token — anonymizing them would break the
    # connection. We can't protect them; make that explicit (notice + leak scan),
    # or refuse the request when BLOCK_MCP_SERVERS is on.
    mcp = body.get("mcp_servers")
    if isinstance(mcp, list) and mcp:
        if config.BLOCK_MCP_SERVERS:
            raise UnscannableContent("mcp_servers")
        events.emit_notice(
            "mcp_servers present — a remote MCP server's URL and authorization "
            "token are forwarded to Anthropic un-anonymized (the connector needs "
            "them). See THREAT-MODEL.", "mcp_servers")
        try:
            anonymizer.scan_for_leaks(json.dumps(mcp), "mcp_servers")
        except Exception:  # noqa: BLE001
            pass
    return body


_SCHEMA_TEXT_KEYS = {"description", "title"}


async def _anon_schema_text(obj) -> None:
    """Anonymize free-text fields (description/title) anywhere in a tool def."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SCHEMA_TEXT_KEYS and isinstance(v, str):
                obj[k] = await _anon_text(v, "tools")
            else:
                await _anon_schema_text(v)
    elif isinstance(obj, list):
        for item in obj:
            await _anon_schema_text(item)


# ── Response deanonymization ──────────────────────────────────────────────────

def _deanon_json_response(data: dict) -> tuple[dict, int]:
    restored: set[str] = set()
    for block in data.get("content", []):
        t = block.get("type")
        if t == "text" and isinstance(block.get("text"), str):
            block["text"], r = anonymizer.deanonymize_detailed(block["text"])
            restored |= r
        elif t == "thinking":
            pass  # pass through unchanged (see _anon_block) — preserve signature
        elif t in ("tool_use", "mcp_tool_use"):
            # Symmetric with _anon_block (and with the streaming path, which
            # restores any input_json_delta): a non-streaming mcp_tool_use must
            # have its surrogate input restored too, or Claude Code gets fake
            # hosts/IPs back. Use the _detailed variant so the restored count is
            # accurate (not just text blocks).
            block["input"], r = anonymizer.deanon_value_detailed(block.get("input", {}))
            restored |= r
        elif t == "mcp_tool_result":
            c = block.get("content")
            if isinstance(c, str):
                block["content"], r = anonymizer.deanonymize_detailed(c)
                restored |= r
            elif isinstance(c, list):
                block["content"], r = anonymizer.deanon_value_detailed(c)
                restored |= r
    if restored:
        log.info("← restored %d surrogate(s) in response", len(restored))
    return data, len(restored)


def _safe_split(buf: str) -> tuple[str, str]:
    """Split into (emit-now, hold). Hold the trailing non-whitespace run, which
    might be the start of a surrogate; surrogates contain no whitespace, so a
    completed one is always fully inside the emitted part."""
    cut = max(buf.rfind(" "), buf.rfind("\n"), buf.rfind("\t"))
    if cut < 0:
        return "", buf
    return buf[:cut + 1], buf[cut + 1:]


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def _deanon_tool_json(raw: str) -> tuple[str, set[str]]:
    """Deanonymize a complete tool_use input JSON string safely.

    Parse → deanonymize each string value → re-serialize, so a restored value
    containing a quote, backslash or newline (a PEM key, a password) stays valid
    JSON. If the buffer isn't valid JSON (shouldn't happen at block stop), fall
    back to a raw text restore of the whole buffer.
    """
    try:
        obj = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return anonymizer.deanonymize_detailed(raw)
    restored: set[str] = set()

    def walk(o):
        if isinstance(o, str):
            out, r = anonymizer.deanonymize_detailed(o)
            restored.update(r)
            return out
        if isinstance(o, dict):
            # Restore keys too — anonymize_value anonymizes them, so streaming
            # tool_use must be symmetric or a surrogate key reaches the tool.
            return {(anonymizer.deanonymize(k) if isinstance(k, str) else k): walk(v)
                    for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return json.dumps(walk(obj)), restored


async def _stream_and_deanon(resp: httpx.Response, client: httpx.AsyncClient, model: str,
                             anon_n: int = 0, anon_new: int = 0):
    """Restore real values in an already-open 200 SSE stream, then close it."""
    text_buf: dict[int, str] = {}
    json_buf: dict[int, str] = {}
    block_type: dict[int, str] = {}
    restored_all: set[str] = set()
    try:
        async for line in resp.aiter_lines():
            if not line.startswith("data:"):
                continue
            data_str = line[len("data:"):].strip()
            if not data_str:
                continue
            try:
                evt = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            etype = evt.get("type")

            if etype == "content_block_start":
                idx = evt.get("index", 0)
                block_type[idx] = evt.get("content_block", {}).get("type", "text")
                text_buf[idx] = ""
                json_buf[idx] = ""
                yield _sse("content_block_start", evt)

            elif etype == "content_block_delta":
                idx = evt.get("index", 0)
                delta = evt.get("delta", {})
                dtype = delta.get("type")
                if dtype == "text_delta":
                    # Buffer, emit up to the last whitespace, restore that part.
                    text_buf[idx] = text_buf.get(idx, "") + delta.get("text", "")
                    emit, hold = _safe_split(text_buf[idx])
                    text_buf[idx] = hold
                    if emit:
                        restored_text, r = anonymizer.deanonymize_detailed(emit)
                        restored_all |= r
                        yield _sse("content_block_delta", {
                            "type": "content_block_delta", "index": idx,
                            "delta": {"type": "text_delta", "text": restored_text}})
                elif dtype == "input_json_delta":
                    # Any *_tool_use block: buffer until stop (JSON stays well-formed).
                    json_buf[idx] = json_buf.get(idx, "") + delta.get("partial_json", "")
                else:
                    # thinking_delta, signature_delta, … pass through UNCHANGED:
                    # thinking only ever contains surrogates (the model saw only
                    # those) and its signature must not be altered.
                    yield _sse("content_block_delta", evt)

            elif etype == "content_block_stop":
                idx = evt.get("index", 0)
                if json_buf.get(idx):                     # a tool_use of any kind
                    restored_json, r = _deanon_tool_json(json_buf[idx])
                    restored_all |= r
                    yield _sse("content_block_delta", {
                        "type": "content_block_delta", "index": idx,
                        "delta": {"type": "input_json_delta", "partial_json": restored_json}})
                elif text_buf.get(idx):                   # flush a text tail
                    restored_tail, r = anonymizer.deanonymize_detailed(text_buf[idx])
                    restored_all |= r
                    yield _sse("content_block_delta", {
                        "type": "content_block_delta", "index": idx,
                        "delta": {"type": "text_delta", "text": restored_tail}})
                text_buf.pop(idx, None)
                json_buf.pop(idx, None)
                yield _sse("content_block_stop", {"type": "content_block_stop", "index": idx})

            else:
                if etype == "message_stop":
                    if restored_all:
                        log.info("← restored %d surrogate(s) in streamed response",
                                 len(restored_all))
                    events.emit_request(model, len(restored_all), anon_n, anon_new)
                yield _sse(etype or "message", evt)
    finally:
        await resp.aclose()
        await client.aclose()


# ── Routes ────────────────────────────────────────────────────────────────────

def _llm_down_response() -> Response:
    return _blocked_response("Local LLM anonymization layer is enabled but unreachable; "
                             "request blocked to avoid leaking un-redacted data.")


def _blocked_response(message: str, status: int = 503) -> Response:
    return Response(
        content=json.dumps({"type": "error",
                            "error": {"type": "anonymizer_blocked", "message": message}}),
        status_code=status, media_type="application/json",
    )


_HINT_TEXT = (
    "Note: some identifiers in this conversation (domain names, hostnames, IP "
    "addresses, usernames, secrets) may appear as randomized placeholders. Treat "
    "them as if they were the real values — use them normally in commands and "
    "answers — and do not comment on, speculate about, or investigate any "
    "anonymization or substitution of these values."
)


def _inject_hint(body: dict) -> None:
    """Append an anti-meta note to the system prompt (opt-in via INJECT_HINT).

    Runs AFTER anonymization — the note is our own text and carries no user data,
    so it is not scanned. Appended at the end so existing prompt-cache prefixes
    are undisturbed."""
    if not config.INJECT_HINT:
        return
    sys = body.get("system")
    if sys is None:
        body["system"] = _HINT_TEXT
    elif isinstance(sys, str):
        body["system"] = (sys + "\n\n" + _HINT_TEXT) if sys else _HINT_TEXT
    elif isinstance(sys, list):
        body["system"] = sys + [{"type": "text", "text": _HINT_TEXT}]


@app.post("/v1/messages")
async def messages(request: Request) -> Response:
    body = await request.json()
    headers = _fwd_headers(request)
    want_stream = bool(body.get("stream", False))

    anonymizer.begin_request()
    try:
        body = await _anon_body(body)
    except llm_detector.LLMUnavailable as exc:
        # Fail-open degradation happens INSIDE _llm (it returns [] instead of
        # raising), so a propagated LLMUnavailable means anonymization did not
        # complete and `body` is still the un-redacted original. Block it — never
        # fall through and forward it, regardless of the fail-open preference.
        log.error("LLM unavailable, blocking request (body not safely anonymized): %s", exc)
        return _llm_down_response()
    except UnscannableContent as exc:
        return _blocked_response(f"request contains an unscannable '{exc}' block "
                                 "(ANONPROXY_BLOCK_UNSCANNABLE=true)")

    try:
        leaks = anonymizer.scan_body_for_leaks(body, "messages")
        if leaks:
            log.warning("%d rotation-worthy secret(s) still present in outgoing body "
                        "(recorded as 'leaked')", leaks)
    except Exception:  # noqa: BLE001 - leak scanning must never break the request
        log.exception("non-fatal: leak scan failed")

    _inject_hint(body)
    model = body.get("model", "?")
    anon_n, anon_new = anonymizer.request_stats()

    if want_stream:
        # Open the stream and check the status BEFORE committing to streaming, so
        # upstream errors keep their real HTTP status, headers (retry-after,
        # anthropic-ratelimit-*, request-id) and error.type — Claude Code needs
        # those for backoff and auto-compact.
        client = httpx.AsyncClient(timeout=600)
        req = client.build_request("POST", f"{config.UPSTREAM_URL}/v1/messages",
                                   json=body, headers=headers)
        resp = await client.send(req, stream=True)
        if resp.status_code != 200:
            raw = await resp.aread()
            hdrs = _resp_headers(resp)
            await resp.aclose()
            await client.aclose()
            return Response(content=anonymizer.deanonymize(raw.decode("utf-8", "replace")),
                            status_code=resp.status_code,
                            headers=hdrs,
                            media_type=resp.headers.get("content-type", "application/json"))
        async def _close():  # belt-and-suspenders if the generator never ran
            await resp.aclose()
            await client.aclose()
        return StreamingResponse(_stream_and_deanon(resp, client, model, anon_n, anon_new),
                                 status_code=200, headers=_resp_headers(resp),
                                 media_type="text/event-stream",
                                 background=BackgroundTask(_close))

    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(f"{config.UPSTREAM_URL}/v1/messages", json=body, headers=headers)
    if resp.status_code != 200:
        return Response(content=anonymizer.deanonymize(resp.text),
                        status_code=resp.status_code, headers=_resp_headers(resp),
                        media_type=resp.headers.get("content-type", "application/json"))
    data, restored = _deanon_json_response(resp.json())
    events.emit_request(model, restored, anon_n, anon_new)
    return Response(content=json.dumps(data), status_code=200, headers=_resp_headers(resp),
                    media_type="application/json")


@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request) -> Response:
    body = await request.json()
    headers = _fwd_headers(request)
    anonymizer.begin_request()
    try:
        body = await _anon_body(body)
    except llm_detector.LLMUnavailable as exc:
        # See messages(): a propagated LLMUnavailable means the body is not safely
        # anonymized — block rather than forward the original.
        log.error("LLM unavailable, blocking count_tokens: %s", exc)
        return _llm_down_response()
    except UnscannableContent as exc:
        return _blocked_response(f"request contains an unscannable '{exc}' block")
    try:
        leaks = anonymizer.scan_body_for_leaks(body, "count_tokens")
        if leaks:
            log.warning("%d rotation-worthy secret(s) still present in outgoing count_tokens "
                        "body (recorded as 'leaked')", leaks)
    except Exception:  # noqa: BLE001
        log.exception("non-fatal: leak scan failed")
    _inject_hint(body)                      # keep token counts in sync with messages()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(f"{config.UPSTREAM_URL}/v1/messages/count_tokens",
                                 json=body, headers=headers)
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/json"))


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "context": config.CONTEXT_ID, "mappings": vault.stats()}


@app.get("/favicon.ico")
async def favicon() -> Response:
    # A browser visiting the dashboard requests this; answer it here so it never
    # falls through to the upstream passthrough (which would forward it to the API
    # and raise spurious "un-anonymized" notices for the browser's own headers).
    return Response(status_code=204)


# ── Live dashboard (registered before the upstream catch-all) ─────────────────

@app.get("/ui")
async def ui_page(request: Request):
    if not config.UI_ENABLED:
        return Response(status_code=404)
    return uiauth.challenge_if_needed(request) or webui.page()


@app.get("/ui/stats")
async def ui_stats(request: Request):
    if not config.UI_ENABLED:
        return Response(status_code=404)
    return uiauth.challenge_if_needed(request) or webui.stats_json()


@app.get("/ui/events")
async def ui_events(request: Request):
    if not config.UI_ENABLED:
        return Response(status_code=404)
    return uiauth.challenge_if_needed(request) or await webui.events_stream(request)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
async def passthrough(request: Request, path: str) -> Response:
    headers = _fwd_headers(request)
    content = await request.body()
    # This path is NOT anonymized. Known content endpoints (/v1/messages,
    # count_tokens) are handled above; anything else with a body is forwarded raw.
    if config.BLOCK_UNKNOWN_ENDPOINTS:
        log.warning("blocked un-anonymized endpoint /%s (ANONPROXY_BLOCK_UNKNOWN=true)", path)
        return _blocked_response(f"endpoint /{path} is not anonymized and blocking is on",
                                 status=403)
    # Unknown endpoint — forwarded WITHOUT anonymization. Surface it regardless of
    # body (a GET like /x?token=ghp_… leaks via the query), and scan the path +
    # query + body for secrets so the leak is at least logged, even though we
    # deliberately don't block or rewrite here.
    events.emit_notice(f"forwarded un-anonymized request to /{_redact_for_display(path)}",
                       request.method)
    if content:
        log.warning("passthrough forwards an un-anonymized %s body for /%s (%d bytes)",
                    request.method, path, len(content))
    try:
        # Scan BOTH the raw query and the URL-decoded values: upstream receives
        # decoded params (dict(request.query_params)), so a percent-encoded secret
        # like ?token=ghp%5F… has no literal "ghp_" in the raw string and would
        # otherwise slip past the token rule. multi_items() keeps duplicate keys.
        parts = [path, str(request.url.query or "")]
        parts += [f"{k}={v}" for k, v in request.query_params.multi_items()]
        if content:
            parts.append(content.decode("utf-8", "replace"))
        anonymizer.scan_for_leaks("\n".join(p for p in parts if p), f"passthrough:{path}")
    except Exception:  # noqa: BLE001
        pass
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.request(request.method, f"{config.UPSTREAM_URL}/{path}",
                                    headers=headers, content=content,
                                    # multi_items() (not dict) so repeated keys
                                    # like ?tag=a&tag=b are forwarded faithfully.
                                    params=request.query_params.multi_items())
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/json"))
