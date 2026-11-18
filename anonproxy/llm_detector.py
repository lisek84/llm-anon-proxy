"""
Optional contextual detection via a local Ollama model.

Catches what regex and the dictionary cannot: bare hostnames, organisation and
person names in prose. Disabled by default (ANONPROXY_LLM=true to enable).

Only entity kinds that genuinely need context are requested from the model;
structural data (IPs, tokens, hashes) is left to the deterministic layers.
"""
import json
import logging
import re

import httpx

from .config import config

log = logging.getLogger("anonproxy.llm")


class LLMUnavailable(RuntimeError):
    pass


_SYSTEM_PROMPT = """\
You identify strings in text that could reveal a real organisation, person, or \
internal system name. Return ONLY contextual entities that a regex cannot find.

FLAG:
HOSTNAME  — bare machine names (DC01, web-prod-01, FILESERVER-PRD)
ORGANIZATION — company/brand/project names; Windows domain/workgroup names
PERSON — real first+last person names
USERNAME — service/domain account names (svc_backup, CORP\\jsmith)

DO NOT FLAG: IPs, CIDRs, hashes, tokens, API keys, emails, URLs (handled elsewhere);
tool names, protocols, product names, versions, CVEs, ports, generic English words.

Return the EXACT substring as it appears. Respond ONLY with JSON:
{"entities":[{"text":"<exact substring>","type":"HOSTNAME|ORGANIZATION|PERSON|USERNAME"}]}
Nothing found: {"entities":[]}"""

_ALLOWED = {"HOSTNAME", "ORGANIZATION", "PERSON", "USERNAME"}


def _extract_json(raw: str) -> str:
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    return m.group(0) if m else raw


async def detect(text: str) -> list[tuple[str, str]]:
    """Return (text, type) contextual matches. Raises LLMUnavailable on failure."""
    if not config.LLM_ENABLED or not text or len(text.strip()) < 12:
        return []
    try:
        async with httpx.AsyncClient(timeout=config.OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{config.OLLAMA_HOST}/api/chat",
                json={
                    "model": config.OLLAMA_MODEL,
                    "think": False,
                    "stream": False,
                    "format": "json",
                    "keep_alive": -1,
                    "options": {"temperature": 0, "num_predict": 400},
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": text},
                    ],
                },
            )
            resp.raise_for_status()
            payload = resp.json()
    except httpx.HTTPError as exc:
        # ANY transport/HTTP failure (connect, timeout, HTTP 500, …) means the
        # LLM layer is not functioning — treat it as unavailable so fail-closed
        # actually blocks, instead of silently degrading to regex+dict.
        raise LLMUnavailable(str(exc)) from exc
    except (ValueError, TypeError) as exc:            # resp.json() on a non-JSON body
        raise LLMUnavailable(f"Ollama returned a non-JSON response: {exc}") from exc

    raw = _message_content(payload)

    return _parse_entities(raw, text)


def _message_content(payload) -> str:
    """Pull message.content as a string, or raise LLMUnavailable. A 200 with a
    malformed shape ({"message": null}, non-string content, …) must become a
    controlled LLMUnavailable, not an AttributeError that bypasses both the
    fail-closed block and the fail-open degrade+notice path."""
    if not isinstance(payload, dict) or not isinstance(payload.get("message"), dict) \
            or not isinstance(payload["message"].get("content"), str):
        raise LLMUnavailable("Ollama response missing a string message.content")
    return payload["message"]["content"]


def _parse_entities(raw: str, text: str) -> list[tuple[str, str]]:
    """Parse Ollama's JSON reply into (text, type) matches. Only an UNPARSEABLE
    reply is a detector failure (-> LLMUnavailable, so fail-closed blocks). A
    small model routinely returns valid JSON that just doesn't follow the
    {"entities":[...]} schema (an empty object, a wrong key, a non-list, odd
    elements); that is NOT an outage — the deterministic dict+regex layers still
    ran, so we treat it as "nothing found" (best-effort) and extract whatever
    well-formed entities are present, rather than blocking real work."""
    try:
        data = json.loads(_extract_json(raw))
    except (ValueError, json.JSONDecodeError) as exc:
        raise LLMUnavailable(f"LLM returned unparseable JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("entities"), list):
        return []   # off-schema but parseable — best-effort: nothing found

    out: list[tuple[str, str]] = []
    for e in data["entities"]:
        if not isinstance(e, dict):
            continue
        val, etype = e.get("text"), e.get("type")
        if not isinstance(val, str) or not isinstance(etype, str):
            continue   # odd element — skip it, don't fail the whole request
        val, etype = val.strip(), etype.strip().upper()
        if val and val in text and etype in _ALLOWED:
            out.append((val, etype))
    return out


async def health_check() -> None:
    """Verify Ollama is reachable and the model present; warm it up."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{config.OLLAMA_HOST}/api/tags")
        resp.raise_for_status()
        names = [m.get("name", "") for m in resp.json().get("models", [])]
    base = config.OLLAMA_MODEL.split(":")[0]
    if not any(n.split(":")[0] == base for n in names):
        raise LLMUnavailable(f"model {config.OLLAMA_MODEL!r} not in Ollama; have {names}")
