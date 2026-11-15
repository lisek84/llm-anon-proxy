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

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from . import anonymizer, dictionary, leaklog, llm_detector, vault
from .config import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("anonproxy")

app = FastAPI(title="anonproxy")

_HOP_BY_HOP = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}


@app.on_event("startup")
async def _startup() -> None:
    vault.init()
    dictionary.load()
    log.info("context=%s upstream=%s llm=%s db=%s",
             config.CONTEXT_ID, config.UPSTREAM_URL, config.LLM_ENABLED, config.DB_PATH)
    log.info("dictionary entries loaded; listening on %s:%s", config.HOST, config.PORT)


def _fwd_headers(request: Request) -> dict[str, str]:
    return {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}


# ── Request anonymization ─────────────────────────────────────────────────────

async def _llm(text: str) -> list[tuple[str, str]]:
    if not config.LLM_ENABLED:
        return []
    return await llm_detector.detect(text)


async def _anon_text(text: str, source: str) -> str:
    matches = await _llm(text)
    return anonymizer.anonymize(text, llm_matches=matches, source=source)


async def _anon_block(block: dict, source: str) -> dict:
    t = block.get("type")
    if t == "text" and isinstance(block.get("text"), str):
        block["text"] = await _anon_text(block["text"], source)
    elif t == "thinking" and isinstance(block.get("thinking"), str):
        block["thinking"] = await _anon_text(block["thinking"], source)
    elif t == "tool_use":
        matches = await _llm(json.dumps(block.get("input", {})))
        block["input"] = anonymizer.anonymize_value(block.get("input", {}), matches, source)
    elif t == "tool_result":
        c = block.get("content")
        if isinstance(c, str):
            block["content"] = await _anon_text(c, source)
        elif isinstance(c, list):
            block["content"] = [await _anon_block(b, source) for b in c]
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
    return body


# ── Response deanonymization ──────────────────────────────────────────────────

def _deanon_json_response(data: dict) -> dict:
    for block in data.get("content", []):
        t = block.get("type")
        if t == "text" and isinstance(block.get("text"), str):
            block["text"] = anonymizer.deanonymize(block["text"])
        elif t == "thinking" and isinstance(block.get("thinking"), str):
            block["thinking"] = anonymizer.deanonymize(block["thinking"])
        elif t == "tool_use":
            block["input"] = anonymizer.deanon_value(block.get("input", {}))
    return data


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


async def _stream_and_deanon(body: dict, headers: dict):
    """Forward as a stream, restoring real values in text and tool_use deltas."""
    text_buf: dict[int, str] = {}
    json_buf: dict[int, str] = {}
    block_type: dict[int, str] = {}

    async with httpx.AsyncClient(timeout=600) as client:
        async with client.stream(
            "POST", f"{config.UPSTREAM_URL}/v1/messages", json=body, headers=headers
        ) as resp:
            if resp.status_code != 200:
                raw = await resp.aread()
                yield _sse("error", {"type": "error",
                                     "error": {"type": "upstream_error",
                                               "message": raw.decode("utf-8", "replace")[:500]}})
                return
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
                    cb = evt.get("content_block", {})
                    block_type[idx] = cb.get("type", "text")
                    text_buf[idx] = ""
                    json_buf[idx] = ""
                    yield _sse("content_block_start", evt)

                elif etype == "content_block_delta":
                    idx = evt.get("index", 0)
                    delta = evt.get("delta", {})
                    dtype = delta.get("type")
                    if dtype in ("text_delta", "thinking_delta"):
                        field = "text" if dtype == "text_delta" else "thinking"
                        text_buf[idx] = text_buf.get(idx, "") + delta.get(field, "")
                        emit, hold = _safe_split(text_buf[idx])
                        text_buf[idx] = hold
                        if emit:
                            out = dict(delta)
                            out[field] = anonymizer.deanonymize(emit)
                            yield _sse("content_block_delta",
                                       {"type": "content_block_delta", "index": idx, "delta": out})
                    elif dtype == "input_json_delta":
                        json_buf[idx] = json_buf.get(idx, "") + delta.get("partial_json", "")
                        # held until block stop (JSON must stay well-formed)
                    else:
                        yield _sse("content_block_delta", evt)

                elif etype == "content_block_stop":
                    idx = evt.get("index", 0)
                    if block_type.get(idx) == "tool_use":
                        restored = anonymizer.deanonymize(json_buf.get(idx, ""))
                        if restored:
                            yield _sse("content_block_delta", {
                                "type": "content_block_delta", "index": idx,
                                "delta": {"type": "input_json_delta", "partial_json": restored},
                            })
                    else:
                        tail = text_buf.get(idx, "")
                        if tail:
                            field = "thinking" if block_type.get(idx) == "thinking" else "text"
                            yield _sse("content_block_delta", {
                                "type": "content_block_delta", "index": idx,
                                "delta": {"type": f"{field}_delta", field: anonymizer.deanonymize(tail)},
                            })
                    text_buf.pop(idx, None)
                    json_buf.pop(idx, None)
                    yield _sse("content_block_stop", {"type": "content_block_stop", "index": idx})

                else:
                    # message_start / ping / message_delta / message_stop / …
                    yield _sse(etype or "message", evt)


# ── Routes ────────────────────────────────────────────────────────────────────

def _llm_down_response() -> Response:
    return Response(
        content=json.dumps({"type": "error", "error": {
            "type": "anonymizer_unavailable",
            "message": "Local LLM anonymization layer is enabled but unreachable; "
                       "request blocked to avoid leaking un-redacted data."}}),
        status_code=503, media_type="application/json",
    )


@app.post("/v1/messages")
async def messages(request: Request) -> Response:
    body = await request.json()
    headers = _fwd_headers(request)
    want_stream = bool(body.get("stream", False))

    try:
        body = await _anon_body(body)
    except llm_detector.LLMUnavailable as exc:
        if config.LLM_FAIL_CLOSED:
            log.error("LLM unavailable, blocking request: %s", exc)
            return _llm_down_response()

    leaks = anonymizer.scan_for_leaks(json.dumps(body), "messages")
    if leaks:
        log.warning("%d secret-shaped value(s) still present in outgoing body "
                    "(recorded as 'leaked' for rotation)", leaks)

    if want_stream:
        return StreamingResponse(_stream_and_deanon(body, headers),
                                 media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(f"{config.UPSTREAM_URL}/v1/messages", json=body, headers=headers)
    if resp.status_code != 200:
        return Response(content=resp.content, status_code=resp.status_code,
                        media_type=resp.headers.get("content-type", "application/json"))
    data = _deanon_json_response(resp.json())
    return Response(content=json.dumps(data), status_code=200, media_type="application/json")


@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request) -> Response:
    body = await request.json()
    headers = _fwd_headers(request)
    try:
        body = await _anon_body(body)
    except llm_detector.LLMUnavailable:
        if config.LLM_FAIL_CLOSED:
            return _llm_down_response()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(f"{config.UPSTREAM_URL}/v1/messages/count_tokens",
                                 json=body, headers=headers)
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/json"))


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "context": config.CONTEXT_ID, "mappings": vault.stats()}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
async def passthrough(request: Request, path: str) -> Response:
    headers = _fwd_headers(request)
    content = await request.body()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.request(request.method, f"{config.UPSTREAM_URL}/{path}",
                                    headers=headers, content=content,
                                    params=dict(request.query_params))
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/json"))
