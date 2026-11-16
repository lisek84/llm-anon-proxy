"""
User dictionary — the first, fully deterministic detection layer.

Loads a small YAML-subset file (top-level keys -> lists of strings) without any
third-party parser, and finds every occurrence of those values in text,
case-insensitively. Each configured value maps to an entity type so the
surrogate has the right shape.
"""
import base64
import json
import logging
import re
import unicodedata
import urllib.parse
from pathlib import Path

from . import regex_detector
from .config import config

log = logging.getLogger("anonproxy.dictionary")

try:
    import ahocorasick  # optional; ~100x faster scan of thousands of literals
    _HAVE_AC = True
except ImportError:  # pragma: no cover - falls back to the regex scanners
    _HAVE_AC = False


def _fold(s: str) -> str:
    """Length-preserving lowercase (so match offsets still index the original).
    A char whose lowercase is a single char is folded; anything else is kept."""
    out = []
    for c in s:
        lc = c.lower()
        out.append(lc if len(lc) == 1 else c)
    return "".join(out)

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
_plain_types: dict[str, str] = {}             # _fold(lit) -> type (O(1) lookup)
_enc_types: dict[str, str] = {}               # lit -> type (case-sensitive)
_plain_auto = None                            # Aho-Corasick over folded text
_enc_auto = None                              # Aho-Corasick over raw text
_ready: bool = False                          # True once load() has run
load_generation: int = 0                      # bumped on every (re)load; caches key on it

_ENC_PRE_SET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
_ENC_POST_SET = _ENC_PRE_SET | {"="}

# An encoded literal is only a real hit when it is not glued to more encoding
# characters, so a shorter encoding never partially matches inside a longer one.
# The preceding class excludes '=' (padding only ends a token, so a '=' before
# our literal means the previous token finished — common in KEY=<base64>); the
# following class includes '=' (a trailing '=' would be this token's padding).
_ENC_PRE = r"[A-Za-z0-9+/_-]"
_ENC_POST = r"[A-Za-z0-9+/=_-]"


def _strip_comment(line: str) -> str:
    """Remove a trailing ' #…' comment, but not a '#' inside quotes or glued to a
    value (so a password like pa#ss or "a # b" survives)."""
    in_q = None
    for i, c in enumerate(line):
        if in_q:
            if c == in_q:
                in_q = None
        elif c in "\"'":
            in_q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _parse_minimal_yaml(text: str) -> dict[str, list[str]]:
    """Parse exactly the shape:  key:\n  - value\n  - value"""
    result: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
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
    global _entries, _scanner, _enc_scanner, _plain_types, _enc_types, load_generation
    global _plain_auto, _enc_auto, _ready
    load_generation += 1
    _ready = True
    p = path or config.DICT_PATH
    _entries = []
    base_values: list[str] = []
    allow_values: list[str] = []
    if p.exists() and p.is_file():  # is_file guards a bind-mount that made a dir
        data = _parse_minimal_yaml(p.read_text(encoding="utf-8"))
        for section, values in data.items():
            if section == "allow":
                allow_values = [v.strip() for v in values if v.strip()]
                continue
            if section not in _SECTION_TYPES:
                log.warning("dictionary: unknown section %r — treating its values as "
                            "generic (did you mean one of %s?)",
                            section, ", ".join(sorted(_SECTION_TYPES)))
            etype = _SECTION_TYPES.get(section, "OTHER")
            for v in values:
                v = _nfc(v.strip())  # canonical Unicode form (so NFD input matches)
                if v:
                    _entries.append((etype, v))
                    base_values.append(v)
    # User allowlist: domains/IPs the regex layer should leave intact.
    regex_detector.set_user_allow(allow_values)

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

    # O(1) type lookups (first declaration of a given literal wins).
    _plain_types = {}
    for t, lit in _entries:
        if t not in _BOUNDARIED_TYPES:
            _plain_types.setdefault(_fold(lit), t)
    _enc_types = {lit: t for t, lit in _entries if t in _BOUNDARIED_TYPES}

    _plain_auto = _enc_auto = None
    _scanner = _enc_scanner = None
    if _HAVE_AC:
        # Aho-Corasick: plain over folded text, encoded over raw text.
        if plain:
            _plain_auto = ahocorasick.Automaton()
            for lit in plain:
                fl = _fold(lit)
                _plain_auto.add_word(fl, (len(fl), fl))
            _plain_auto.make_automaton()
        if encoded:
            _enc_auto = ahocorasick.Automaton()
            for lit in encoded:
                _enc_auto.add_word(lit, (len(lit), lit))
            _enc_auto.make_automaton()
    else:
        # Regex fallback. Plain is substring + case-insensitive; encoded is
        # token-bounded and case-sensitive.
        _scanner = re.compile("|".join(re.escape(x) for x in plain), re.IGNORECASE) if plain else None
        _enc_scanner = (
            re.compile(f"(?<!{_ENC_PRE})(?:" + "|".join(re.escape(x) for x in encoded)
                       + f")(?!{_ENC_POST})")
            if encoded else None
        )


def _type_for(matched: str) -> str:
    return _plain_types.get(_fold(matched), "OTHER")


def _type_for_exact(literal: str) -> str:
    return _enc_types.get(literal, "ENCODED_B64")


def _enc_bounded(text: str, start: int, end: int) -> bool:
    """True if text[start:end+1] is not glued to more encoding characters."""
    if start > 0 and text[start - 1] in _ENC_PRE_SET:
        return False
    if end + 1 < len(text) and text[end + 1] in _ENC_POST_SET:
        return False
    return True


def detect(text: str) -> list[tuple[str, str]]:
    """Return distinct (matched_text, entity_type) for every dictionary hit."""
    if not _ready:
        load()
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    if _plain_auto is not None or _enc_auto is not None:
        if _plain_auto is not None:
            folded = _fold(text)
            for end, (length, fl) in _plain_auto.iter(folded):
                matched = text[end - length + 1:end + 1]      # original case
                if matched not in seen:
                    seen.add(matched)
                    out.append((matched, _plain_types.get(fl, "OTHER")))
        if _enc_auto is not None:
            for end, (length, lit) in _enc_auto.iter(text):
                start = end - length + 1
                if lit not in seen and _enc_bounded(text, start, end):
                    seen.add(lit)
                    out.append((lit, _enc_types.get(lit, "ENCODED_B64")))
        return out

    # Regex fallback
    if _scanner is not None:
        for m in _scanner.finditer(text):
            matched = m.group(0)
            if matched not in seen:
                seen.add(matched)
                out.append((matched, _type_for(matched)))
    if _enc_scanner is not None:
        for m in _enc_scanner.finditer(text):
            matched = m.group(0)
            if matched not in seen:
                seen.add(matched)
                out.append((matched, _type_for_exact(matched)))
    return out
