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
import bisect
import contextvars
import hashlib
import logging
import re
import unicodedata
from collections import OrderedDict

from . import audit, dictionary, events, regex_detector, surrogates, vault, leaklog
from .config import config

log = logging.getLogger("anonproxy")

# ── Per-block LRU cache ───────────────────────────────────────────────────────
# Claude Code resends the whole conversation history every turn, so the same
# blocks are anonymized again and again. The transformation is deterministic
# given (context, dictionary, secret key), so we cache text -> anonymized text.
# The key folds in the dictionary generation and the secret fingerprint, so a
# dictionary reload or key rotation invalidates it automatically.
_CACHE_MAX = 4096
_cache: "OrderedDict[str, str]" = OrderedDict()


def _cache_key(text: str, source: str) -> str:
    h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return (f"{config.CONTEXT_ID}|{dictionary.load_generation}|{vault.generation}|"
            f"{surrogates.secret_fingerprint()}|{source}|{h}")


def clear_cache() -> None:
    _cache.clear()


# Per-request accounting (so the dashboard can show "anonymized N (M new)" and,
# in verbose mode, re-show each distinct value once per request). Request-scoped
# via a contextvar so concurrent requests don't mix.
_req: "contextvars.ContextVar[dict | None]" = contextvars.ContextVar("anon_req", default=None)


def begin_request() -> None:
    """Start per-request anonymization accounting (call once per request)."""
    _req.set({"vals": set(), "new": 0})


def request_stats() -> tuple[int, int]:
    """(# distinct values anonymized this request, # of them new to the vault)."""
    st = _req.get()
    return (len(st["vals"]), st["new"]) if st else (0, 0)


def _resolve_spans(spans: list[tuple]) -> list[tuple]:
    """Pick non-overlapping spans, longest first, returned sorted by start.

    Each span is (start, end, …). Accepted spans stay disjoint and sorted, so an
    overlap check only has to look at the two neighbours found by bisect — O(n log
    n) instead of the O(n²) all-pairs scan.
    """
    starts: list[int] = []
    ends: list[int] = []
    accepted: list[tuple] = []
    for span in sorted(spans, key=lambda s: s[1] - s[0], reverse=True):
        s0, s1 = span[0], span[1]
        i = bisect.bisect_right(starts, s0)
        if i > 0 and ends[i - 1] > s0:        # overlaps the interval on the left
            continue
        if i < len(starts) and starts[i] < s1:  # overlaps the interval on the right
            continue
        starts.insert(i, s0)
        ends.insert(i, s1)
        accepted.insert(i, span)
    return accepted

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
    # shell / dev / SSH vocabulary a small model loves to flag as ORG/USERNAME
    "wsl", "wsl2", "ssh-agent", "agent", "socket", "sock", "env", "home", "path",
    "bashrc", "zshrc", "profile", "deploy", "rsa", "dsa", "ecdsa", "ed25519",
    "keygen", "pubkey", "github", "gitlab", "bitbucket", "aws", "gcp", "azure",
    "k8s", "kubernetes", "pod", "namespace", "cron", "crontab", "bash", "zsh",
    "python", "python3", "node", "npm", "pnpm", "yarn", "pip", "venv", "make",
    "tmux", "vim", "sudo", "systemd", "compose", "kubectl", "ollama", "anthropic",
    "shell", "term", "lang", "pwd", "editor", "pager", "display", "tmpdir", "tty",
})

_CVE_RE = re.compile(r"(?i)^cve-\d{4}-\d{3,}$")
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)+[a-z]?$")
# Suffixes that mark a file / key / config name, not a person/org/host name.
_SAFE_SUFFIXES = ("_deploy", "_rsa", "_dsa", "_ecdsa", "_ed25519", ".sock", ".pem",
                  ".key", ".pub", ".crt", ".conf", ".cfg", ".yaml", ".yml", ".json",
                  ".log", ".sh", ".py", ".txt", ".md")


def _llm_is_safe(value: str) -> bool:
    """True if an LLM-flagged value should be IGNORED (not sensitive). A small
    local model over-flags technical vocabulary — file paths, env vars, option
    labels, tool/platform names — as ORG/USERNAME/HOSTNAME, which garbles the
    conversation. Reject those structurally; the dictionary still catches real
    values you listed."""
    v = value.strip()
    low = v.lower()
    if not v or low in _SAFE_LLM_TERMS:
        return True
    if _CVE_RE.match(v) or _VERSION_RE.match(v) or len(v) < 3 or v.isdigit():
        return True
    # File paths, env-var refs, flags, dotfiles — not person/org/host NAMES.
    if "/" in v or v[0] in "~$-." or low.endswith(_SAFE_SUFFIXES):
        return True
    # Env vars / constants / UI mode labels: ALL-CAPS with an underscore or space
    # (SSH_AUTH_SOCK, SUGGESTION MODE). NOT bare all-caps or hyphenated ones — a
    # real hostname like BACKUP-NODE-07 is all-caps + hyphen and must still match.
    letters = [c for c in v if c.isalpha()]
    if letters and all(c.isupper() for c in letters) and ("_" in v or " " in v):
        return True
    # A grammatical suffix on a safe term (Polish "WSL-u", "SSH-a", "Dockera"…).
    if "-" in low and low.rsplit("-", 1)[0] in _SAFE_LLM_TERMS:
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

    # Subdomain preservation: if a regex FQDN (e.g. cdn3.example.com) strictly
    # contains a dictionary DOMAIN (example.com), drop the longer FQDN so only
    # the registrable part is swapped and the cdn3. subdomain structure is kept.
    #
    # This fires ONLY when the longer match is ITSELF a DOMAIN. An EMAIL, a
    # CREDENTIAL or a TOKEN that merely contains a dictionary domain must be kept
    # and replaced whole — otherwise only the domain part is swapped and the rest
    # (the email's local part, a password's prefix/suffix) leaks. Keeping it means
    # longest-match-first replaces the whole value and the inner domain span is
    # skipped as an overlap.
    for key in list(entities):
        if key in dict_vals or entities[key] != "DOMAIN":
            continue
        if any(d != key and d in key and dtype == "DOMAIN"
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

    # Cache repeated blocks (resent history). Only when the LLM layer did not
    # contribute matches, so the result depends solely on (text, dict, key).
    use_cache = not llm_matches
    if use_cache:
        ck = _cache_key(text, source)
        hit = _cache.get(ck)
        if hit is not None:
            _cache.move_to_end(ck)
            return hit

    def _store(result: str) -> str:
        if use_cache:
            _cache[ck] = result
            _cache.move_to_end(ck)
            if len(_cache) > _CACHE_MAX:
                _cache.popitem(last=False)
        return result

    entities = _collect(text, llm_matches)
    if not entities:
        return _store(text)

    # Position-based replacement over the ORIGINAL text, in a single pass, so a
    # surrogate just inserted is never re-scanned (e.g. a keyword "example" must
    # not match inside a domain surrogate's ".example" TLD). Overlapping matches
    # are resolved longest-first.
    spans: list[tuple[int, int, str, str]] = []  # (start, end, original, etype)
    for original, etype in entities.items():
        start = 0
        while True:
            i = text.find(original, start)
            if i < 0:
                break
            spans.append((i, i + len(original), original, etype))
            start = i + len(original)

    # Accept non-overlapping spans, preferring the longest (sorted by start).
    accepted = _resolve_spans(spans)

    # Resolve surrogates once per distinct original (first use records it).
    new_count = 0
    seen_types: dict[str, int] = {}
    surrogate_of: dict[str, str] = {}
    st = _req.get()
    for _, _, original, etype in accepted:
        if original in surrogate_of:
            continue
        surrogate, is_new = vault.get_or_create(original, etype, surrogates.generate)
        surrogate_of[original] = surrogate
        seen_types[etype] = seen_types.get(etype, 0) + 1
        # First time this value is seen in THIS request? (for the per-request count
        # and to re-show it once per request in verbose mode).
        first_in_req = (original not in st["vals"]) if st is not None else is_new
        if st is not None:
            st["vals"].add(original)
            if is_new:
                st["new"] += 1
        # Logging/telemetry is best-effort: it must never break anonymization
        # (the substitution is already decided above) nor the request path.
        try:
            if is_new:
                new_count += 1
                audit.record(original, surrogate, etype, source)
            # Dashboard: show a catch the first time ever, and — in verbose mode —
            # once per request so you can see the substitutions happen each turn.
            if first_in_req and (is_new or config.UI_VERBOSE):
                events.emit_catch(source, etype, original, surrogate)
            if etype in leaklog.ROTATABLE:
                leaklog.record(original, etype, "intercepted", source)
        except Exception:  # noqa: BLE001
            log.exception("non-fatal: failed to record catch for %s", etype)

    # Stitch the output from the original text and the accepted spans.
    out_parts: list[str] = []
    cursor = 0
    for s0, s1, original, _ in accepted:
        out_parts.append(text[cursor:s0])
        out_parts.append(surrogate_of[original])
        cursor = s1
    out_parts.append(text[cursor:])
    result = "".join(out_parts)

    if seen_types:
        summary = " ".join(f"{t.lower()}={n}" for t, n in sorted(seen_types.items()))
        msg = "anonymized %d value(s) [%s] (%d new): %s"
        args = (sum(seen_types.values()), source, new_count, summary)
        # New catches are worth seeing live; steady-state re-sends stay quiet.
        (log.info if new_count else log.debug)(msg, *args)

    return _store(result)


# Only high-confidence, rotation-worthy secrets are recorded as "leaked".
# Hashes/checksums and protocol ids are too noisy (and not things you rotate).
_LEAK_SCAN_TYPES = frozenset({"CREDENTIAL", "TOKEN"})

# Request fields that are protocol/transport, not user content — never scanned.
# metadata.user_id is the caller's own Anthropic account id (64-hex): it must go
# upstream anyway and is not a secret to rotate, so scanning it just cries wolf.
_LEAK_SKIP_KEYS = frozenset({"metadata"})


def _record_leak(val: str, etype: str, source: str) -> int:
    if etype not in _LEAK_SCAN_TYPES:
        return 0
    # Our own shape-preserving surrogates (e.g. a fake ghp_ token) match the same
    # patterns — skip anything already known to the vault as a surrogate.
    if vault.surrogate_exists(val):
        return 0
    leaklog.record(val, etype, "leaked", source)
    return 1


def scan_for_leaks(text: str, source: str = "outgoing") -> int:
    """Scan one already-anonymized string for rotation-worthy secrets that
    slipped through, recording them as 'leaked'. Returns the count found."""
    count = 0
    for val, etype in regex_detector.detect(text):
        count += _record_leak(val, etype, source)
    return count


def _iter_strings(obj, skip_keys: frozenset[str]):
    """Yield every string value in a JSON-like structure, skipping subtrees
    under keys in skip_keys."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in skip_keys:
                continue
            yield from _iter_strings(v, skip_keys)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v, skip_keys)


def scan_body_for_leaks(body, source: str = "outgoing") -> int:
    """Scan the string VALUES of an outgoing request body (not its JSON
    serialization, which would create escape-boundary false positives), skipping
    protocol fields like `metadata`. Records rotation-worthy leaks. Returns count.
    """
    count = 0
    for s in _iter_strings(body, _LEAK_SKIP_KEYS):
        for val, etype in regex_detector.detect(s):
            count += _record_leak(val, etype, source)
    return count


_DOMAIN_SUR_BASE = re.compile(r"^[a-z]{3,9}-[a-z]{3,9}$")


def _domain_surrogate_base(surrogate: str) -> str | None:
    """For a domain surrogate (…label1-label2.example), return the distinctive
    base 'label1-label2'; else None. Used to restore a base the model left bare
    after dropping the '.example' TLD."""
    if not surrogate.endswith(".example"):
        return None
    reg = surrogates._registrable(surrogate)        # label1-label2.example
    base = reg[: -len(".example")] if reg.endswith(".example") else ""
    return base if _DOMAIN_SUR_BASE.match(base) else None


def deanonymize_detailed(text: str) -> tuple[str, set[str]]:
    """Return (restored_text, set of surrogates that were actually replaced).

    Position-based over the original text, one pass: a restored original is never
    re-scanned, so a surrogate that happens to be a substring of another
    mapping's original can't cause a double or wrong replacement. Overlapping
    surrogate matches are resolved longest-first.
    """
    if not text:
        return text, set()

    reverse = vault.all_reverse_mappings()
    spans: list[tuple[int, int, str]] = []  # (start, end, original)
    for surrogate, original in reverse:
        if not surrogate:
            continue
        start = 0
        while True:
            i = text.find(surrogate, start)
            if i < 0:
                break
            spans.append((i, i + len(surrogate), original))
            start = i + len(surrogate)

    # Second pass — restore a DOMAIN surrogate's bare base. The model often drops
    # the ".example" TLD or recombines labels (especially in tables), leaving our
    # distinctive base ("ab-cd", or "sub.ab-cd") orphaned; match it and restore
    # the registrable domain. The base is a random letters-hyphen-letters token,
    # so matching it in prose is unambiguous. Full ".example" forms matched above
    # win via longest-match; here we skip a base followed by '.'/'-'/alnum.
    for surrogate, original in reverse:
        if not surrogate or "@" in original:
            continue
        base = _domain_surrogate_base(surrogate)
        if not base:
            continue
        orig = surrogates._registrable(original)
        start = 0
        while True:
            i = text.find(base, start)
            if i < 0:
                break
            end = i + len(base)
            before = text[i - 1] if i > 0 else ""
            after = text[end] if end < len(text) else ""
            if not (before.isalnum() or after.isalnum() or after in "-."):
                spans.append((i, end, orig))
            start = end

    accepted = _resolve_spans(spans)

    out: list[str] = []
    cursor = 0
    restored: set[str] = set()
    for s0, s1, original in accepted:
        out.append(text[cursor:s0])
        out.append(original)
        restored.add(text[s0:s1])
        cursor = s1
    out.append(text[cursor:])
    return "".join(out), restored


def deanonymize(text: str) -> str:
    """Replace every known surrogate with its original (longest surrogate first)."""
    return deanonymize_detailed(text)[0]


def anonymize_value(obj, llm_matches=None, source: str = ""):
    """Recursively anonymize all strings inside a JSON-like structure, keys
    included — a sensitive value can appear as a JSON key, not only a value.
    Keys are restored symmetrically by deanon_value."""
    if isinstance(obj, str):
        return anonymize(obj, llm_matches=llm_matches, source=source)
    if isinstance(obj, dict):
        return {anonymize(k, llm_matches=llm_matches, source=source) if isinstance(k, str) else k:
                anonymize_value(v, llm_matches, source) for k, v in obj.items()}
    if isinstance(obj, list):
        return [anonymize_value(v, llm_matches, source) for v in obj]
    return obj


def deanon_value(obj):
    """Recursively deanonymize all strings inside a JSON-like structure (keys too)."""
    return deanon_value_detailed(obj)[0]


def deanon_value_detailed(obj) -> tuple[object, set[str]]:
    """Like deanon_value, but also returns the set of surrogates actually
    replaced — so callers (e.g. restoring tool_use / mcp_tool_* in a non-streaming
    response) can report an accurate 'restored' count, not just for text blocks."""
    restored: set[str] = set()

    def walk(o):
        if isinstance(o, str):
            out, r = deanonymize_detailed(o)
            restored.update(r)
            return out
        if isinstance(o, dict):
            return {(walk(k) if isinstance(k, str) else k): walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(obj), restored
