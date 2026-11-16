"""
Deterministic regex safety net.

Returns (value, entity_type) pairs where `value` is the exact substring to
replace — for assignment-style secrets only the value is captured, never the
surrounding key. The anonymizer resolves overlaps by replacing longest first.
"""
import re

# Domains that are tooling/ecosystem, not the user's own infrastructure.
_DOMAIN_ALLOWLIST = {
    "anthropic.com", "claude.com", "claude.ai", "github.com", "githubusercontent.com",
    "gitlab.com", "pypi.org", "npmjs.com", "debian.org", "ubuntu.com", "python.org",
    "nmap.org", "example.com", "example.org", "example.net", "localhost",
    "schema.org", "w3.org", "googleapis.com", "cloudflare.com", "letsencrypt.org",
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
_add("DOMAIN", rf"(?i)\b(?:{_LBL}\.)+(?:{_AMBIG})(?=[:/])")              # trailing :port / /path
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
_IP_ALLOWLIST = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.169.254",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "::1",
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
            if etype == "EMAIL" and _DSN_BEFORE.search(text[:mstart]):
                continue  # "pass@host" in a DSN — not an email
            if etype == "IP_ADDRESS" and (val in _IP_ALLOWLIST or val in _USER_ALLOW):
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
            key = (val, etype)
            if key in seen:
                continue
            seen.add(key)
            out.append((val, etype))
    return out
