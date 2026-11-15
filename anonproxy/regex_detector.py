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
_add("CIDR", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/\d{1,2}\b")
_add("IP_ADDRESS", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# ── Email + domains ───────────────────────────────────────────────────────────
_add("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_add("DOMAIN",
     r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
     r"(?:com|net|org|io|dev|app|pl|eu|uk|de|co|info|biz|local|internal|lan|cloud|xyz|me)\b")

# IPs we never anonymize (loopback / well-known resolvers / metadata / unspecified).
_IP_ALLOWLIST = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.169.254",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "::1",
}


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
            val = val.strip().strip("'\"")
            if not val:
                continue
            if etype == "IP_ADDRESS" and val in _IP_ALLOWLIST:
                continue
            if etype == "DOMAIN":
                low = val.lower().rstrip(".")
                if low in _DOMAIN_ALLOWLIST or any(
                    low == d or low.endswith("." + d) for d in _DOMAIN_ALLOWLIST
                ):
                    continue
            key = (val, etype)
            if key in seen:
                continue
            seen.add(key)
            out.append((val, etype))
    return out
