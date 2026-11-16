"""
Anonymization orchestration.

Pipeline for a piece of text:
  1. dictionary  — deterministic, highest priority (your own values, right type)
  2. regex       — structural safety net (IPs, tokens, credentials, hashes…)
  3. llm         — optional contextual layer (hostnames/org/person in prose)
  4. merge       — dictionary type wins; then regex structural types win
  5. replace     — longest original first, via the vault (stable surrogates)
  6. rotate-log  — note secret-shaped values as "intercepted"

Deanonymization replaces every known surrogate with its original, longest
surrogate first, over arbitrary JSON-ish structures (so tool_use inputs are
restored to real values before Claude Code executes them).
"""
import logging
import re
import unicodedata

from . import audit, dictionary, events, regex_detector, surrogates, vault, leaklog

log = logging.getLogger("anonproxy")

# LLM-sourced matches are filtered against these (regex/dictionary are trusted).
# Tool names, protocols, platform terms and generic labels the model sometimes
# over-flags. Lowercased membership test.
_SAFE_LLM_TERMS = frozenset({
    # recon / offensive-security tooling commonly seen in logs
    "nmap", "masscan", "nikto", "gobuster", "ffuf", "sqlmap", "hydra", "nuclei",
    "metasploit", "msfconsole", "mimikatz", "bloodhound", "crackmapexec", "impacket",
    "responder", "hashcat", "john", "netcat", "curl", "wget", "ssh", "scp", "rsync",
    "kubectl", "helm", "terraform", "docker", "ansible", "git", "systemctl", "journalctl",
    # protocols / services
    "http", "https", "ftp", "sftp", "smb", "cifs", "nfs", "rdp", "ldap", "ldaps",
    "kerberos", "dns", "dhcp", "snmp", "smtp", "imap", "pop3", "ntp", "winrm", "wmi",
    "tcp", "udp", "icmp", "tls", "ssl", "vpn", "bgp", "ospf",
    # platform / k8s / cloud generic
    "kube-system", "kube-public", "default", "ingress", "nginx", "apache", "iis",
    "mysql", "postgres", "postgresql", "redis", "mongodb", "sqlite", "nodejs",
    "ubuntu", "debian", "centos", "rhel", "alpine", "windows", "linux",
    # AD/network generic labels (not org-specific)
    "workgroup", "domain", "administrator", "administrators", "guest", "krbtgt",
    "domain users", "domain admins", "enterprise admins", "pdc", "bdc", "dns server",
    # generic nouns the model mislabels as entities
    "server", "client", "host", "hostname", "user", "username", "service", "account",
    "cluster", "node", "network", "gateway", "firewall", "router", "switch", "portal",
})

_CVE_RE = re.compile(r"(?i)^cve-\d{4}-\d{3,}$")
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)+[a-z]?$")


def _llm_is_safe(value: str) -> bool:
    """True if an LLM-flagged value should be ignored (not sensitive)."""
    v = value.strip()
    low = v.lower()
    if low in _SAFE_LLM_TERMS:
        return True
    if _CVE_RE.match(v) or _VERSION_RE.match(v):
        return True
    if len(v) < 3:
        return True
    if v.isdigit():
        return True
    return False

# Regex is authoritative for these structural types even if the LLM disagrees.
_REGEX_WINS = frozenset({
    "IP_ADDRESS", "CIDR", "MAC_ADDRESS", "TOKEN", "HASH", "CREDENTIAL",
    "EMAIL", "DOMAIN",
})


def _collect(text: str, llm_matches: list[tuple[str, str]] | None) -> dict[str, str]:
    """Return {original_text: entity_type}, applying precedence rules."""
    entities: dict[str, str] = {}

    # 3 (lowest priority): LLM contextual, with a deterministic safe-term guard.
    for val, etype in (llm_matches or []):
        if val and val in text and not _llm_is_safe(val):
            entities[val] = etype

    # 2: regex overrides LLM for structural types.
    for val, etype in regex_detector.detect(text):
        if val in entities and entities[val] in _REGEX_WINS:
            continue
        entities[val] = etype

    # 1 (highest): dictionary always wins — your own values, correct type.
    dict_vals: dict[str, str] = {}
    for val, etype in dictionary.detect(text):
        entities[val] = etype
        dict_vals[val] = etype

    # Subdomain preservation: if a longer detection (e.g. a regex FQDN
    # cdn3.onlyfans.com) strictly contains a dictionary DOMAIN (onlyfans.com),
    # drop the longer one so only the registrable part is swapped and the
    # cdn3. subdomain structure is kept. This applies ONLY to domain values —
    # a brand/org word that happens to sit inside a domain must NOT suppress
    # replacing the whole FQDN.
    preserve_structure = {"DOMAIN"}
    for key in list(entities):
        if key in dict_vals:
            continue
        if any(d != key and d in key and dtype in preserve_structure
               for d, dtype in dict_vals.items()):
            del entities[key]

    return entities


def anonymize(text: str, llm_matches: list[tuple[str, str]] | None = None,
              source: str = "") -> str:
    """Replace every detected original with its surrogate."""
    if not text or not text.strip():
        return text

    # Canonical Unicode form so differently-normalized input (e.g. NFD from some
    # filesystems/JSON) still matches dictionary values stored in NFC. This is
    # semantically identical text — safe to forward.
    text = unicodedata.normalize("NFC", text)

    entities = _collect(text, llm_matches)
    if not entities:
        return text

    # Longest original first prevents partial/overlapping substitutions.
    result = text
    new_count = 0
    seen_types: dict[str, int] = {}
    for original, etype in sorted(entities.items(), key=lambda kv: len(kv[0]), reverse=True):
        if original not in result:
            continue
        surrogate, is_new = vault.get_or_create(original, etype, surrogates.generate)
        result = result.replace(original, surrogate)
        seen_types[etype] = seen_types.get(etype, 0) + 1
        if is_new:
            new_count += 1
            audit.record(original, surrogate, etype, source)
            events.emit_catch(source, etype, original, surrogate)
        if etype in leaklog.ROTATABLE:
            leaklog.record(original, etype, "intercepted", source)

    if seen_types:
        summary = " ".join(f"{t.lower()}={n}" for t, n in sorted(seen_types.items()))
        msg = "anonymized %d value(s) [%s] (%d new): %s"
        args = (sum(seen_types.values()), source, new_count, summary)
        # New catches are worth seeing live; steady-state re-sends stay quiet.
        (log.info if new_count else log.debug)(msg, *args)

    return result


def scan_for_leaks(text: str, source: str = "outgoing") -> int:
    """Scan already-anonymized text for secret-shaped values that slipped
    through, and record them as 'leaked' (they are about to reach the API).
    Returns the number of distinct leaks found."""
    count = 0
    for val, etype in regex_detector.detect(text):
        if etype not in leaklog.ROTATABLE:
            continue
        # Our own shape-preserving surrogates (e.g. a fake ghp_ token) match the
        # same patterns — skip anything already known to the vault as a surrogate.
        if vault.surrogate_exists(val):
            continue
        leaklog.record(val, etype, "leaked", source)
        count += 1
    return count


def deanonymize_detailed(text: str) -> tuple[str, set[str]]:
    """Return (restored_text, set of surrogates that were actually replaced)."""
    if not text:
        return text, set()
    result = text
    restored: set[str] = set()
    for surrogate, original in vault.all_reverse_mappings():
        if surrogate in result:
            result = result.replace(surrogate, original)
            restored.add(surrogate)
    return result, restored


def deanonymize(text: str) -> str:
    """Replace every known surrogate with its original (longest surrogate first)."""
    return deanonymize_detailed(text)[0]


def anonymize_value(obj, llm_matches=None, source: str = ""):
    """Recursively anonymize all strings inside a JSON-like structure."""
    if isinstance(obj, str):
        return anonymize(obj, llm_matches=llm_matches, source=source)
    if isinstance(obj, dict):
        return {k: anonymize_value(v, llm_matches, source) for k, v in obj.items()}
    if isinstance(obj, list):
        return [anonymize_value(v, llm_matches, source) for v in obj]
    return obj


def deanon_value(obj):
    """Recursively deanonymize all strings inside a JSON-like structure."""
    if isinstance(obj, str):
        return deanonymize(obj)
    if isinstance(obj, dict):
        return {k: deanon_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deanon_value(v) for v in obj]
    return obj
