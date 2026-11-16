"""
User dictionary — the first, fully deterministic detection layer.

Loads a small YAML-subset file (top-level keys -> lists of strings) without any
third-party parser, and finds every occurrence of those values in text,
case-insensitively. Each configured value maps to an entity type so the
surrogate has the right shape.
"""
import base64
import json
import re
import unicodedata
import urllib.parse
from pathlib import Path

from .config import config

# Encoded forms of a dictionary value shorter than this are not registered, to
# avoid matching trivial strings that merely look like an encoding.
_MIN_ENCODED_LEN = 8

# Types matched with token boundaries (pure alphabets that can partially overlap).
# Everything else — including the structured URL/JSON encodings — is matched as
# a plain substring, case-insensitively.
_BOUNDARIED_TYPES = frozenset({"ENCODED_B64", "ENCODED_B32", "ENCODED_HEX"})


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)

_SECTION_TYPES = {
    "domains": "DOMAIN",
    "hosts": "HOSTNAME",
    "ips": "IP_ADDRESS",
    "cidrs": "CIDR",
    "emails": "EMAIL",
    "usernames": "USERNAME",
    "organizations": "ORGANIZATION",
    "persons": "PERSON",
    "paths": "PATH",
    "tokens": "TOKEN",
    "credentials": "CREDENTIAL",
    # A bare brand/project word to catch wherever it appears as a component:
    # /var/www/example, example.conf, sites-enabled/example, etc. Matched as
    # a substring; because longer dictionary/regex values win first (longest
    # match first), a full domain like example.com is still handled as a domain.
    "keywords": "KEYWORD",
    "other": "OTHER",
}

# (entity_type, literal) pairs and the scanning regexes.
_entries: list[tuple[str, str]] = []
_scanner: re.Pattern | None = None            # plain literals, substring match
_enc_scanner: re.Pattern | None = None        # encoded literals, token-bounded

# An encoded literal is only a real hit when it is not glued to more encoding
# characters, so a shorter encoding never partially matches inside a longer one.
# The preceding class excludes '=' (padding only ends a token, so a '=' before
# our literal means the previous token finished — common in KEY=<base64>); the
# following class includes '=' (a trailing '=' would be this token's padding).
_ENC_PRE = r"[A-Za-z0-9+/_-]"
_ENC_POST = r"[A-Za-z0-9+/=_-]"


def _parse_minimal_yaml(text: str) -> dict[str, list[str]]:
    """Parse exactly the shape:  key:\n  - value\n  - value"""
    result: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t", "-")) and line.endswith(":"):
            current = line[:-1].strip().lower()
            result[current] = []
        elif line.lstrip().startswith("-") and current is not None:
            val = line.lstrip()[1:].strip().strip('"').strip("'")
            if val:
                result[current].append(val)
    return result


def _encoded_variants(value: str) -> list[tuple[str, str]]:
    """Return (entity_type, encoded_literal) for reversible encodings of value.

    Covers the trivial, keyless transforms that would otherwise smuggle a known
    value past substitution: base64 (standard + url-safe, padded + unpadded,
    with and without the trailing newline `echo` adds) and hex. One-way hashes
    (md5/sha) of standard length are already scrubbed by the regex HASH rule.
    """
    out: list[tuple[str, str]] = []
    raws = {value.encode(), (value + "\n").encode()}  # printf vs echo; always UTF-8
    for raw in raws:
        b64 = {
            base64.b64encode(raw).decode(),
            base64.b64encode(raw).decode().rstrip("="),
            base64.urlsafe_b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode().rstrip("="),
        }
        for enc in b64:
            out.append(("ENCODED_B64", enc))
        b32 = base64.b32encode(raw).decode()
        out.append(("ENCODED_B32", b32))
        out.append(("ENCODED_B32", b32.rstrip("=")))

    hx = value.encode().hex()
    out.append(("ENCODED_HEX", hx))
    out.append(("ENCODED_HEX", hx.upper()))

    # Structured encodings (contain delimiters) — matched as plain substrings.
    url = urllib.parse.quote(value, safe="")              # %XX of UTF-8 bytes
    out.append(("URL_ENCODED", url))
    jsesc = json.dumps(value)[1:-1]                       # \uXXXX / \n / \" etc.
    out.append(("JSON_ESCAPED", jsesc))

    # Drop anything too short, or identical to the value (pure-ASCII url/json).
    return [(t, e) for t, e in out if len(e) >= _MIN_ENCODED_LEN and e != value]


def load(path: Path | None = None) -> None:
    """(Re)load the dictionary and rebuild the scanner."""
    global _entries, _scanner, _enc_scanner
    p = path or config.DICT_PATH
    _entries = []
    base_values: list[str] = []
    if p.exists() and p.is_file():  # is_file guards a bind-mount that made a dir
        data = _parse_minimal_yaml(p.read_text(encoding="utf-8"))
        for section, values in data.items():
            etype = _SECTION_TYPES.get(section, "OTHER")
            for v in values:
                v = _nfc(v.strip())  # canonical Unicode form (so NFD input matches)
                if v:
                    _entries.append((etype, v))
                    base_values.append(v)

    # Also catch common reversible encodings of each declared value.
    seen = {lit for _, lit in _entries}
    for v in base_values:
        for etype, enc in _encoded_variants(v):
            if enc not in seen:
                _entries.append((etype, enc))
                seen.add(enc)

    # Longest literals first so e.g. example.com wins over example.
    _entries.sort(key=lambda e: len(e[1]), reverse=True)

    plain = [lit for t, lit in _entries if t not in _BOUNDARIED_TYPES]
    encoded = [lit for t, lit in _entries if t in _BOUNDARIED_TYPES]

    # Plain values match as substrings (so a domain covers its subdomains);
    # case-insensitive. Encoded values must be token-bounded and are
    # case-sensitive (base64/hex are case-significant).
    _scanner = re.compile("|".join(re.escape(x) for x in plain), re.IGNORECASE) if plain else None
    _enc_scanner = (
        re.compile(f"(?<!{_ENC_PRE})(?:" + "|".join(re.escape(x) for x in encoded)
                   + f")(?!{_ENC_POST})")
        if encoded else None
    )


def _type_for(literal_lower: str) -> str:
    for etype, lit in _entries:
        if lit.lower() == literal_lower:
            return etype
    return "OTHER"


def _type_for_exact(literal: str) -> str:
    for etype, lit in _entries:
        if lit == literal:
            return etype
    return "ENCODED_B64"


def detect(text: str) -> list[tuple[str, str]]:
    """Return (matched_text, entity_type) for every dictionary hit in text."""
    if _scanner is None and _enc_scanner is None:
        load()
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    if _scanner is not None:
        for m in _scanner.finditer(text):
            matched = m.group(0)
            if matched not in seen:
                seen.add(matched)
                out.append((matched, _type_for(matched.lower())))
    if _enc_scanner is not None:
        for m in _enc_scanner.finditer(text):
            matched = m.group(0)
            if matched not in seen:
                seen.add(matched)
                out.append((matched, _type_for_exact(matched)))
    return out
