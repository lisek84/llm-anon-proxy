"""
Dictionary builder — fill dictionary.yaml from stdin, files, or the system,
so you don't have to think up every value by hand.

Pipe-friendly, one section at a time:

    cat /etc/hosts        | python -m anonproxy.gendict ips
    cat /etc/hosts        | python -m anonproxy.gendict hosts
    cat .env app.conf     | python -m anonproxy.gendict domains
    python -m anonproxy.gendict ips 10.0.0.0/24 /etc/network/interfaces

Everything it can detect, from files or stdin, as a ready dictionary:

    cat *.conf .env       | python -m anonproxy.gendict all
    python -m anonproxy.gendict all /etc/nginx/sites-enabled/*

Scan the machine's usual sources (hosts, nginx/apache/haproxy, ssh config,
/etc/passwd, .env) and build a starting dictionary:

    python -m anonproxy.gendict auto

Append/merge straight into your dictionary (dedupes, keeps what's there):

    cat /etc/hosts | python -m anonproxy.gendict ips --merge dictionary.yaml

Notes
  * Domains that are public tooling (github.com, docker.io, …) are dropped, so
    you only capture YOUR infrastructure. Pass --keep-known to keep them.
  * It emits identifiers only — never secrets/passwords (those are caught live by
    the regex layer; a dictionary is not a secret store). Review before trusting.
"""
import ipaddress
import os
import re
import sys
from pathlib import Path

# Section -> dictionary key. Order is the emit order.
_SECTIONS = ["domains", "hosts", "ips", "cidrs", "emails", "urls", "usernames", "paths"]

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_CIDR = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/\d{1,2}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.I)
_FQDN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
_HOSTLABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_ABS_PATH = re.compile(r"(?<![\w])/(?:[\w.-]+/){1,}[\w.-]+")

# final labels that mean "not a real domain" (file extensions, local-only zones)
_NOT_TLD = frozenset((
    "conf", "config", "yaml", "yml", "json", "txt", "log", "py", "sh", "rb", "js",
    "ts", "md", "cfg", "ini", "service", "socket", "sock", "pid", "lock", "bak",
    "tmp", "example", "local", "localdomain", "localhost", "arpa", "d",
))  # note: internal/lan/home/corp are kept — private zones worth anonymizing


def _looks_like_domain(dl: str) -> bool:
    return "." in dl and dl.rsplit(".", 1)[1] not in _NOT_TLD


def _known_domains() -> set:
    from . import regex_detector
    return set(regex_detector._DOMAIN_ALLOWLIST)


def _is_public_domain(d: str, known: set) -> bool:
    d = d.lower().rstrip(".")
    return any(d == k or d.endswith("." + k) for k in known)


def _extract(section: str, text: str, keep_known: bool) -> list[str]:
    out: list[str] = []
    if section == "ips":
        for m in _IPV4.finditer(text):
            if text[m.end():m.end() + 1] == "/":   # part of a CIDR, not a bare host
                continue
            try:
                ip = ipaddress.ip_address(m.group())
            except ValueError:
                continue
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local \
                    or str(ip) in ("255.255.255.255", "169.254.169.254"):
                continue
            out.append(m.group())
    elif section == "cidrs":
        out = _CIDR.findall(text)
    elif section == "emails":
        out = _EMAIL.findall(text)
    elif section == "urls":
        out = [u.rstrip(".,);") for u in _URL.findall(text)]
    elif section == "paths":
        out = [p for p in _ABS_PATH.findall(text) if len(p) > 4]
    elif section == "domains":
        known = set() if keep_known else _known_domains()
        for d in _FQDN.findall(text):
            dl = d.lower().rstrip(".")
            if dl.replace(".", "").isdigit():      # that's an IP, not a domain
                continue
            if not _looks_like_domain(dl):         # filename / loopback zone
                continue
            if not keep_known and _is_public_domain(dl, known):
                continue
            out.append(dl)
    elif section == "hosts":
        out = _extract_hosts(text)
    elif section == "usernames":
        out = _extract_usernames(text)
    # dedupe, preserve order
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def _extract_hosts(text: str) -> list[str]:
    """Bare hostnames: /etc/hosts fields after the IP (no dots), lone-token lines,
    and `Host`/`Hostname` lines from an ssh config."""
    hosts = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith(("host ", "hostname ")):
            for tok in line.split()[1:]:
                if _HOSTLABEL.match(tok) and not tok.isdigit():
                    hosts.append(tok)
            continue
        toks = line.split()
        # /etc/hosts style: first token an IP, rest are names
        is_hostsfile = False
        try:
            ip = ipaddress.ip_address(toks[0])
            is_hostsfile = True
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                continue   # localhost / ip6-* aliases — noise, not real hosts
        except (ValueError, IndexError):
            pass
        cand = toks[1:] if is_hostsfile else (toks if len(toks) == 1 else [])
        for t in cand:
            if "." not in t and _HOSTLABEL.match(t) and not t.isdigit() and len(t) > 1 \
                    and t != "localhost" and not t.startswith("ip6-"):
                hosts.append(t)
    return hosts


def _extract_usernames(text: str) -> list[str]:
    """Real login users from /etc/passwd (uid >= 1000, has a shell), else plain tokens."""
    users = []
    passwd_like = False
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit():
            passwd_like = True
            uid = int(parts[2])
            shell = parts[6].strip()
            if uid >= 1000 and uid < 65534 and not shell.endswith(("nologin", "false")):
                users.append(parts[0])
    if not passwd_like:
        for line in text.splitlines():
            t = line.strip()
            if t and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", t):
                users.append(t)
    return users


# ── auto scan ─────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _auto_scan(keep_known: bool) -> dict[str, list[str]]:
    import glob
    import socket
    result: dict[str, set] = {s: set() for s in _SECTIONS}

    # hostnames / this machine
    for name in {socket.gethostname(), socket.getfqdn()}:
        name = name.strip()
        if name and name.lower() not in ("localhost", "localhost.localdomain"):
            if _looks_like_domain(name.lower()):
                result["domains"].add(name.lower())
            elif "." not in name:
                result["hosts"].add(name)

    text_sources = [
        "/etc/hosts", "/etc/hostname", "/etc/haproxy/haproxy.cfg",
        os.path.expanduser("~/.ssh/config"), "/etc/passwd",
    ]
    text_sources += glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/sites-available/*")
    text_sources += glob.glob("/etc/nginx/conf.d/*.conf")
    text_sources += glob.glob("/etc/apache2/sites-enabled/*") + glob.glob("/etc/apache2/sites-available/*")
    text_sources += [".env", "config/.env"] + glob.glob("*.conf")

    for src in text_sources:
        text = _read(src)
        if not text:
            continue
        if src.endswith("passwd"):
            result["usernames"].update(_extract_usernames(text))
            continue
        for section in ("ips", "cidrs", "emails", "domains", "hosts", "urls"):
            result[section].update(_extract(section, text, keep_known))
        # nginx server_name / apache ServerName / ServerAlias
        for m in re.finditer(r"(?im)^\s*(?:server_name|ServerName|ServerAlias)\s+([^;]+)", text):
            for tok in m.group(1).replace(";", " ").split():
                tok = tok.strip().lower()
                if not tok or tok == "_" or tok.startswith("$"):
                    continue
                if _looks_like_domain(tok):
                    result["domains"].add(tok)
                elif "." not in tok:
                    result["hosts"].add(tok)
    if not keep_known:
        known = _known_domains()
        result["domains"] = {d for d in result["domains"] if not _is_public_domain(d, known)}
    return {s: sorted(v) for s, v in result.items() if v}


# ── emit / merge ──────────────────────────────────────────────────────────────

def _to_yaml(sections: dict[str, list[str]]) -> str:
    lines = ["# Generated by: python -m anonproxy.gendict — REVIEW before using.",
             "# Identifiers only (never secrets). Merge into dictionary.yaml.", ""]
    # standard sections first, then any extra keys (allow, keywords, …) as-is
    keys = [k for k in _SECTIONS if sections.get(k)] + \
           [k for k in sections if k not in _SECTIONS and sections.get(k)]
    for key in keys:
        lines.append(f"{key}:")
        lines += [f"  - {v}" for v in sections[key]]
        lines.append("")
    return "\n".join(lines)


def _merge_into(path: str, new: dict[str, list[str]]) -> int:
    from . import dictionary
    existing = {}
    p = Path(path)
    if p.exists():
        existing = dictionary._parse_minimal_yaml(p.read_text(encoding="utf-8"))
    added = 0
    merged: dict[str, list[str]] = {}
    for key in set(list(existing) + list(new)):
        cur = [v.strip() for v in existing.get(key, []) if v.strip()]
        seen = set(cur)
        for v in new.get(key, []):
            if v not in seen:
                cur.append(v)
                seen.add(v)
                added += 1
        if cur:
            merged[key] = cur
    # keep non-standard sections (e.g. allow, keywords) as-is
    ordered = {k: merged[k] for k in _SECTIONS if k in merged}
    for k in merged:
        if k not in ordered:
            ordered[k] = merged[k]
    p.write_text(_to_yaml(ordered), encoding="utf-8")
    return added


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="python -m anonproxy.gendict", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=_SECTIONS + ["all", "auto"],
                    help="a section to extract, 'all' (every type), or 'auto' (scan the system)")
    ap.add_argument("files", nargs="*", help="input files (default: stdin, unless 'auto')")
    ap.add_argument("--merge", metavar="FILE", help="merge the result into this dictionary.yaml")
    ap.add_argument("-o", "--out", metavar="FILE", help="write YAML here instead of stdout")
    ap.add_argument("--keep-known", action="store_true",
                    help="keep public tooling domains (github.com, docker.io, …)")
    args = ap.parse_args()

    if args.what == "auto":
        sections = _auto_scan(args.keep_known)
    else:
        if args.files:
            text = "\n".join(_read(f) for f in args.files)
        elif not sys.stdin.isatty():
            text = sys.stdin.read()
        else:
            ap.error("no input — pass files or pipe via stdin (e.g. cat /etc/hosts | … ips)")
        targets = _SECTIONS if args.what == "all" else [args.what]
        sections = {s: v for s in targets if (v := _extract(s, text, args.keep_known))}

    total = sum(len(v) for v in sections.values())
    if args.merge:
        added = _merge_into(args.merge, sections)
        print(f"merged {added} new value(s) into {args.merge} "
              f"(found {total}). Review it, then restart the proxy.", file=sys.stderr)
        return 0
    yaml = _to_yaml(sections)
    if args.out:
        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote {total} value(s) to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(yaml)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
