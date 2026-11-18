"""
Deterministic regex safety net.

Returns (value, entity_type) pairs where `value` is the exact substring to
replace — for assignment-style secrets only the value is captured, never the
surrounding key. The anonymizer resolves overlaps by replacing longest first.
"""
import ipaddress
import re

from . import plid
from .config import config

# Public tooling/ecosystem domains — not the user's own infrastructure, and the
# model needs them for context (they also fill Claude Code's own system prompt).
# Covers the domain itself and any subdomain. Your real domains go in the dict.
_DOMAIN_ALLOWLIST = {
    # Anthropic / Claude
    "anthropic.com", "claude.com", "claude.ai",
    # code hosting
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "sourceforge.net",
    # package registries / language ecosystems
    "pypi.org", "pythonhosted.org", "npmjs.com", "npmjs.org", "jsdelivr.net",
    "unpkg.com", "crates.io", "rubygems.org", "packagist.org", "nuget.org",
    "hex.pm", "pub.dev", "golang.org", "go.dev", "rust-lang.org", "nodejs.org",
    "python.org", "ruby-lang.org", "php.net", "maven.org", "gradle.org",
    # container registries
    "docker.io", "docker.com", "ghcr.io", "quay.io", "gcr.io", "registry.k8s.io",
    "k8s.io", "kubernetes.io", "helm.sh",
    # linux distros / core projects
    "debian.org", "ubuntu.com", "canonical.com", "archlinux.org",
    "fedoraproject.org", "redhat.com", "centos.org", "alpinelinux.org",
    "kernel.org", "gnu.org", "apache.org", "nginx.org", "nginx.com", "haproxy.org",
    "postgresql.org", "mariadb.org", "mysql.com", "redis.io", "mongodb.com",
    "hashicorp.com", "terraform.io", "letsencrypt.org", "openssl.org",
    # docs / reference / cloud providers (public endpoints)
    "google.com", "gstatic.com", "googleapis.com", "google.internal",
    "metadata.google.internal", "cloudflare.com", "amazonaws.com", "azure.com",
    "microsoft.com", "mozilla.org", "readthedocs.io", "readthedocs.org",
    "stackoverflow.com", "nmap.org", "schema.org", "w3.org",
    # placeholders / loopback
    "example.com", "example.org", "example.net", "localhost",
}

# Each rule: (entity_type, pattern, group). group 'v' captures the value; 0 = whole.
_RULES: list[tuple[str, re.Pattern, object]] = []


def _add(etype: str, pattern: str, group: object = 0, flags: int = 0) -> None:
    _RULES.append((etype, re.compile(pattern, flags), group))


# ── Private keys / PEM blocks (whole block) ───────────────────────────────────
_add("CREDENTIAL",
     r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
     0, re.DOTALL)

# ── Unix crypt / htpasswd hashes ($id$salt$hash) ──────────────────────────────
_add("CREDENTIAL", r"\$(?:apr1|1|2[aby]?|5|6)\$[./A-Za-z0-9]{1,}\$?[./A-Za-z0-9]+")

# ── Cloud / service tokens ────────────────────────────────────────────────────
_add("TOKEN", r"\bAKIA[0-9A-Z]{16}\b")
_add("TOKEN", r"\bASIA[0-9A-Z]{16}\b")
_add("TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")
_add("TOKEN", r"\bsk_live_[A-Za-z0-9]{16,}\b")
_add("TOKEN", r"\bsk_test_[A-Za-z0-9]{16,}\b")
_add("TOKEN", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
# Slack/Discord-style webhook URL: the path token after …/services/T…/B…/ is the
# secret (the host gets anonymized separately, so the token must be caught here).
_add("TOKEN", r"(?i)hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/(?P<v>[A-Za-z0-9]{8,})", "v")
_add("TOKEN", r"(?i)discord(?:app)?\.com/api/webhooks/\d+/(?P<v>[A-Za-z0-9_-]{16,})", "v")
_add("TOKEN", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")  # JWT
_add("TOKEN", r"\bAIza[0-9A-Za-z_-]{35}\b")  # Google API key
_add("TOKEN", r"\bglpat-[A-Za-z0-9_-]{20,}\b")  # GitLab PAT

# ── Assignment-style credentials (capture the value only) ─────────────────────
# KEY=value / KEY: value for secret-ish keys
_add("CREDENTIAL",
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
     r"private[_-]?key|auth[_-]?token|client[_-]?secret|db[_-]?pass\w*)"
     r"\s*[:=]\s*(?P<v>'[^']+'|\"[^\"]+\"|[^\s,;]+)", "v")
# define('DB_PASSWORD', 'value')  (PHP / wp-config)
_add("CREDENTIAL",
     r"(?i)define\(\s*['\"][A-Z_]*(?:PASS|SECRET|KEY|SALT)[A-Z_]*['\"]\s*,\s*"
     r"(?P<v>'[^']+'|\"[^\"]+\")", "v")
# CLI -p<value> / -p <value> / --password <value>. The flag must be a real
# token (start of string or preceded by whitespace), so it never fires inside a
# word like "of-prod-db01".
_add("CREDENTIAL",
     r"(?i)(?<!\S)(?:--password|--pass|-p)[=\s]?(?P<v>'[^']+'|\"[^\"]+\"|[^\s'\"]{3,})", "v")
# redis requirepass
_add("CREDENTIAL", r"(?i)\brequirepass\s+(?P<v>'[^']+'|\"[^\"]+\"|\S+)", "v")
# sshpass -p
_add("CREDENTIAL", r"(?i)\bsshpass\s+-p\s*(?P<v>'[^']+'|\"[^\"]+\"|\S+)", "v")
# Authorization: Bearer / Basic
_add("CREDENTIAL", r"(?i)\b(?:Bearer|Basic)\s+(?P<v>[A-Za-z0-9+/._~=-]{16,})", "v")
# HAProxy stats auth  (stats auth <user>:<password>) — keyword-gated, so no FP
_add("CREDENTIAL", r"(?i)\bstats\s+auth\s+[^\s:]+:(?P<v>\S+)", "v")
# Credentials embedded in URLs: proto://user:pass@host
_add("CREDENTIAL", r"(?i)[a-z][a-z0-9+.\-]*://[^:/\s]+:(?P<v>[^@/\s]+)@", "v")

# ── Hashes (standalone hex) ───────────────────────────────────────────────────
_add("HASH", r"\b[0-9a-fA-F]{32}\b")   # MD5 / NTLM
_add("HASH", r"\b[0-9a-fA-F]{40}\b")   # SHA1
_add("HASH", r"\b[0-9a-fA-F]{64}\b")   # SHA256
# NTLM pair LM:NT
_add("HASH", r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")

# ── Network identifiers ───────────────────────────────────────────────────────
_add("MAC_ADDRESS", r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
# Guards reject only a digit, or a digit+dot, on each side — so the address is
# not a slice of a longer dotted-number run (SNMP OIDs), yet a trailing '.' (end
# of sentence) or '.label' (PTR name) is fine and the IP is still caught.
# (?<![vV]) drops v4.14.5.1-style version strings.
_IP = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_IP_PRE = r"(?<!\d)(?<!\d\.)(?<![vV])"
_IP_POST = r"(?!\d)(?!\.\d)"
_add("CIDR", rf"{_IP_PRE}{_IP}/\d{{1,2}}(?!\d)")
_add("IP_ADDRESS", rf"{_IP_PRE}{_IP}{_IP_POST}")

# IPv6. The regex is a permissive-but-bounded candidate; every match is then
# validated with `ipaddress` in detect(), which rejects MACs, times and hex runs
# far more reliably than regex alone. Covers full, compressed (::) and
# v4-mapped/embedded forms. Order: CIDR before address so fd00::/48 is one unit.
_H = r"[0-9A-Fa-f]{1,4}"
_IPV6 = (
    rf"::(?:ffff(?::0{{1,4}})?:)?{_IP}"           # ::ffff:1.2.3.4 (v4-mapped) — first,
    rf"|(?:{_H}:){{1,4}}:{_IP}"                   # 1:2:3:4::1.2.3.4 (embedded v4) so the
    rf"|(?:{_H}:){{7}}{_H}"                       # dotted tail is consumed whole, not as hex
    rf"|(?:{_H}:){{1,7}}:"                        # 1::   1:2:3:4:5:6:7::
    rf"|(?:{_H}:){{1,6}}:{_H}"                    # 1::8  1:2:3:4:5:6::8
    rf"|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}"
    rf"|(?:{_H}:){{1,4}}(?::{_H}){{1,3}}"
    rf"|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}"
    rf"|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}"
    rf"|{_H}:(?::{_H}){{1,6}}"
    rf"|:(?::{_H}){{1,7}}"                        # ::8  ::2:3:4:5:6:7:8
)
_IP6_PRE = r"(?<![0-9A-Za-z:.])"
_add("CIDR", rf"{_IP6_PRE}(?:{_IPV6})/\d{{1,3}}(?!\d)")
_add("IP_ADDRESS", rf"{_IP6_PRE}(?:{_IPV6})(?![0-9A-Za-z:/])")

# ── Polish national identifiers (validated by checksum in detect()) ───────────
# Bare, low false-positive after validation (date+checksum / 14-digit checksum):
_add("PESEL", r"\b\d{11}\b")
_add("REGON", r"\b\d{14}\b")
# NIP / REGON-9 only in a clear context — their 10/9-digit length otherwise
# collides with timestamps/phone numbers at ~9-10% even after the checksum:
_add("NIP", r"(?i)\bNIP\b[\s:]*(?P<v>\d{10})\b", "v")
_add("NIP", r"(?i)\bPL(?P<v>\d{10})\b", "v")                 # EU VAT form
_add("REGON", r"(?i)\bREGON\b[\s:]*(?P<v>\d{9})\b", "v")
# Bare 10-digit NIP / 9-digit REGON — gated behind DETECT_PL_ID_BARE:
_add("NIP_BARE", r"\b\d{10}\b")
_add("REGON_BARE", r"\b\d{9}\b")

# ── Email + domains ───────────────────────────────────────────────────────────
_add("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# "Strong" TLDs: unlikely to collide with a file extension or a code field, so a
# plain two-label domain (foo.com) is caught directly.
_STRONG_TLDS = (
    "com net org biz cloud xyz gg edu gov mil int eu asia "
    "pl de uk fr nl be ch cz sk hu ro bg gr pt ie dk se fi "
    "ru ua by lt lv ee "
    "us ca mx br ar cl pe uy "
    "cn jp kr sg th vn ph hk tw au nz za ke ma eg "
    "local internal lan intra home corp"
).split()
# "Ambiguous" TLDs that double as file extensions or code attributes
# (README.md, deploy.sh, user.id, obj.app, socket.io). These are only treated as
# a domain with >=3 labels (api.x.ai) or in a clear network context (after @ or
# ://, or with a trailing :port or /path). Your own such domains go in the dict.
_AMBIG_TLDS = (
    "md sh so in ai tv it at id my ng me is no es io app dev info co"
).split()

_LBL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_STRONG = "|".join(_STRONG_TLDS)
_AMBIG = "|".join(_AMBIG_TLDS)
_NOCALL = r"(?!\s*\()"   # skip function calls:  logger.info ("x")

_add("DOMAIN", rf"(?i)\b(?:{_LBL}\.)+(?:{_STRONG})\b{_NOCALL}")
_add("DOMAIN", rf"(?i)\b(?:{_LBL}\.){{2,}}(?:{_AMBIG})\b{_NOCALL}")      # >=3 labels
# trailing :port (digits, not file:line:) or /path
_add("DOMAIN", rf"(?i)\b(?:{_LBL}\.)+(?:{_AMBIG})(?=:\d{{1,5}}(?![\d:])|/)")
_add("DOMAIN", rf"(?i)(?<=@)(?:{_LBL}\.)+(?:{_AMBIG})\b{_NOCALL}")       # user@host
_add("DOMAIN", rf"(?i)(?<=//)(?:{_LBL}\.)+(?:{_AMBIG})\b{_NOCALL}")      # proto://host

# A DSN password@host (proto://user:pass@host) makes the EMAIL rule greedily
# match "pass@host" — detect that so the password is handled by the
# credentials-in-URL rule and the host is left to the DOMAIN rule.
_DSN_BEFORE = re.compile(r"://[^/\s:]+:$")

# Tokens that look like a domain but are code, not infrastructure — never flagged.
_DOMAIN_CODE_DENYLIST = {
    "socket.io", "log.info", "log.debug", "log.error", "log.warn", "console.log",
    "self.app", "settings.local", "os.path", "string.format", "self.config",
    "this.app", "process.env",
}

# IPs we never anonymize (loopback / well-known resolvers / metadata / unspecified).
# Universal VCS / service SSH accounts — the same for everyone, not personal PII.
_EMAIL_ALLOWLIST = {
    "git@github.com", "git@gitlab.com", "git@bitbucket.org", "git@ssh.github.com",
    "hg@bitbucket.org", "aur@aur.archlinux.org",
}

_IP_ALLOWLIST = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.169.254",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "::1",
}

# IPv6 we never anonymize, stored in normalized form for comparison (loopback,
# unspecified, public resolvers: Google, Cloudflare, Quad9).
_IP6_ALLOWLIST = {
    str(ipaddress.ip_address(x)) for x in (
        "::1", "::",
        "2001:4860:4860::8888", "2001:4860:4860::8844",   # Google
        "2606:4700:4700::1111", "2606:4700:4700::1001",   # Cloudflare
        "2620:fe::fe", "2620:fe::9",                       # Quad9
    )
}

# User-configurable allowlist (the dictionary's `allow:` section). Public
# services the model should keep seeing (hetzner.com, docker.io, grafana.com…).
_USER_ALLOW: set[str] = set()


def set_user_allow(values) -> None:
    global _USER_ALLOW
    _USER_ALLOW = {v.lower().rstrip(".") for v in values if v}


def detect(text: str) -> list[tuple[str, str]]:
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for etype, pattern, group in _RULES:
        for m in pattern.finditer(text):
            val = m.group(group) if group != 0 else m.group(0)
            if not val:
                continue
            mstart = m.start(group) if group != 0 else m.start()
            val = val.strip().strip("'\"")
            if not val:
                continue
            if etype == "EMAIL" and _DSN_BEFORE.search(text[max(0, mstart - 256):mstart]):
                continue  # "pass@host" in a DSN — not an email (window keeps this O(1))
            if etype == "EMAIL" and (val.lower() in _EMAIL_ALLOWLIST or val.lower() in _USER_ALLOW):
                continue  # universal VCS/service accounts — not personal PII
            if etype in ("IP_ADDRESS", "CIDR") and ":" in val:
                # IPv6 (or v6 CIDR): validate with ipaddress — this is what
                # actually rejects regex false positives (MACs, times, hex).
                try:
                    host = val.split("/")[0]
                    norm = str(ipaddress.ip_address(host))
                    if "/" in val:
                        ipaddress.ip_network(val, strict=False)
                except ValueError:
                    continue
                if norm in _IP6_ALLOWLIST or val.lower() in _USER_ALLOW:
                    continue
            elif etype == "IP_ADDRESS" and (val in _IP_ALLOWLIST or val in _USER_ALLOW):
                continue
            if etype == "DOMAIN":
                low = val.lower().rstrip(".")
                if low in _DOMAIN_CODE_DENYLIST:
                    continue
                if low in _DOMAIN_ALLOWLIST or any(
                    low == d or low.endswith("." + d) for d in _DOMAIN_ALLOWLIST
                ):
                    continue
                if low in _USER_ALLOW or any(
                    low == d or low.endswith("." + d) for d in _USER_ALLOW
                ):
                    continue
            if etype in _PL_TYPES:
                if not config.DETECT_PL_ID:
                    continue
                base = "NIP" if etype.startswith("NIP") else \
                       "REGON" if etype.startswith("REGON") else "PESEL"
                ok = (plid.valid_pesel(val) if base == "PESEL" else
                      plid.valid_nip(val) if base == "NIP" else plid.valid_regon(val))
                if not ok:
                    continue
                if etype.endswith("_BARE") and not config.DETECT_PL_ID_BARE:
                    continue
                etype = base
            key = (val, etype)
            if key in seen:
                continue
            seen.add(key)
            out.append((val, etype))
    return out


_PL_TYPES = frozenset({"PESEL", "NIP", "REGON", "NIP_BARE", "REGON_BARE"})
