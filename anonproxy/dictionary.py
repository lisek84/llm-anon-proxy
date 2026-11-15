"""
User dictionary — the first, fully deterministic detection layer.

Loads a small YAML-subset file (top-level keys -> lists of strings) without any
third-party parser, and finds every occurrence of those values in text,
case-insensitively. Each configured value maps to an entity type so the
surrogate has the right shape.
"""
import re
from pathlib import Path

from .config import config

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
    "other": "OTHER",
}

# (entity_type, literal) pairs and a combined scanning regex.
_entries: list[tuple[str, str]] = []
_scanner: re.Pattern | None = None


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


def load(path: Path | None = None) -> None:
    """(Re)load the dictionary and rebuild the scanner."""
    global _entries, _scanner
    p = path or config.DICT_PATH
    _entries = []
    if p.exists():
        data = _parse_minimal_yaml(p.read_text(encoding="utf-8"))
        for section, values in data.items():
            etype = _SECTION_TYPES.get(section, "OTHER")
            for v in values:
                v = v.strip()
                if v:
                    _entries.append((etype, v))
    # Longest literals first so e.g. onlyfans.com wins over onlyfans.
    _entries.sort(key=lambda e: len(e[1]), reverse=True)
    if _entries:
        alternation = "|".join(re.escape(lit) for _, lit in _entries)
        _scanner = re.compile(alternation, re.IGNORECASE)
    else:
        _scanner = None


def _type_for(literal_lower: str) -> str:
    for etype, lit in _entries:
        if lit.lower() == literal_lower:
            return etype
    return "OTHER"


def detect(text: str) -> list[tuple[str, str]]:
    """Return (matched_text, entity_type) for every dictionary hit in text."""
    if _scanner is None:
        load()
    if _scanner is None or not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _scanner.finditer(text):
        matched = m.group(0)
        if matched in seen:
            continue
        seen.add(matched)
        out.append((matched, _type_for(matched.lower())))
    return out
