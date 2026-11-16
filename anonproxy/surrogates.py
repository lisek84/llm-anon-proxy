"""
Deterministic, structure-preserving surrogate generation.

A surrogate is derived from HMAC(secret, context|type|original|attempt), so:
  * the same original always yields the same surrogate (stable across restarts);
  * the surrogate reveals nothing about the original without the local secret;
  * passing a higher `attempt` yields a different candidate, which the vault
    uses to resolve the rare hash collision — guaranteeing a 1:1 reverse map.

Shapes are preserved so the model still reasons usefully and so restored
output stays valid:
  * domains keep their sub-labels; only the registrable part is swapped
    (cdn3.example.com -> cdn3.aqurel-vous.example)
  * public IPs -> 198.18.0.0/15 (RFC 2544 benchmark range, non-routable)
  * private IPs stay private (10.x), preserving the public/internal distinction
  * credentials/tokens keep their length class
"""
import hashlib
import hmac
import os
import stat
import string

from .config import config

_secret: bytes | None = None


def _load_secret() -> bytes:
    global _secret
    if _secret is not None:
        return _secret
    path = config.SECRET_KEY_PATH
    if path.exists():
        _secret = path.read_bytes()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        _secret = os.urandom(32)
        path.write_bytes(_secret)
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
    return _secret


def secret_fingerprint() -> str:
    """Short, non-reversible fingerprint of the current secret key. Changes when
    the key is rotated, so caches that depend on surrogate values can key on it."""
    return hashlib.sha256(b"fp\x00" + _load_secret()).hexdigest()[:16]


def _digest(entity_type: str, original: str, attempt: int) -> bytes:
    msg = f"{config.CONTEXT_ID}\x00{entity_type}\x00{original}\x00{attempt}".encode()
    return hmac.new(_load_secret(), msg, hashlib.sha256).digest()


def _rand_from(digest: bytes, alphabet: str, length: int) -> str:
    # Expand the digest deterministically to the required length.
    out = []
    i = 0
    cur = digest
    while len(out) < length:
        if i >= len(cur):
            cur = hashlib.sha256(cur).digest()
            i = 0
        out.append(alphabet[cur[i] % len(alphabet)])
        i += 1
    return "".join(out)


_LOWER = string.ascii_lowercase
_ALNUM = string.ascii_letters + string.digits


def _fake_domain(original: str, attempt: int) -> str:
    d = _digest("DOMAIN", original, attempt)
    label1 = _rand_from(d, _LOWER, 6)
    label2 = _rand_from(d[8:], _LOWER, 5)
    return f"{label1}-{label2}.example"


def _fake_hostname(original: str, attempt: int) -> str:
    d = _digest("HOSTNAME", original, attempt)
    return "host-" + _rand_from(d, string.digits, 4)


def _fake_ipv4(original: str, attempt: int, private: bool) -> str:
    d = _digest("IP_ADDRESS", original, attempt)
    if private:
        return f"10.{d[0]}.{d[1]}.{1 + d[2] % 254}"
    # 198.18.0.0/15 — reserved for benchmarking, never routed publicly.
    second = 18 + (d[0] % 2)
    return f"198.{second}.{d[1]}.{1 + d[2] % 254}"


def _fake_cidr(original: str, attempt: int, private: bool) -> str:
    base = _fake_ipv4(original, attempt, private)
    prefix = original.split("/")[-1] if "/" in original else "24"
    octets = base.split(".")
    octets[3] = "0"
    return ".".join(octets) + "/" + prefix


def _fake_email(original: str, attempt: int) -> str:
    d = _digest("EMAIL", original, attempt)
    user = _rand_from(d, _LOWER, 7)
    dom = _rand_from(d[8:], _LOWER, 6)
    return f"{user}@{dom}.example"


# Lowercase + digits: short surrogates must be long enough and mixed enough that
# they never occur naturally in model output / tool commands, where they would be
# wrongly restored as a substring (deanonymize matches without word boundaries).
_LOWER_DIGITS = _LOWER + string.digits


def _fake_username(original: str, attempt: int) -> str:
    d = _digest("USERNAME", original, attempt)
    return "user_" + _rand_from(d, _LOWER_DIGITS, 8)


def _fake_person(original: str, attempt: int) -> str:
    # A single whitespace-free pseudonym token. No surrogate may contain a space:
    # the streaming restorer emits up to the last whitespace, so a space inside a
    # surrogate could split it across chunks and prevent it being restored.
    d = _digest("PERSON", original, attempt)
    first = _rand_from(d, _LOWER, 5).capitalize()
    last = _rand_from(d[8:], _LOWER, 6).capitalize()
    return f"{first}{last}"


def _fake_org(original: str, attempt: int) -> str:
    d = _digest("ORGANIZATION", original, attempt)
    return _rand_from(d, _LOWER, 1).capitalize() + _rand_from(d[8:], _LOWER_DIGITS, 8)


def _fake_keyword(original: str, attempt: int) -> str:
    # Lowercase+digits slug with no dots/spaces, so it slots into paths and
    # filenames (/var/www/<slug>, <slug>.conf). Min 8 + a digit mix so it never
    # collides with a natural substring on the way back.
    d = _digest("KEYWORD", original, attempt)
    length = max(8, min(len(original), 14))
    return _rand_from(d, _LOWER_DIGITS, length)


def _len_class(n: int) -> int:
    # Preserve an order-of-magnitude length so the model keeps proportion.
    for cls in (8, 12, 16, 20, 24, 32, 40, 64, 128):
        if n <= cls:
            return cls
    return 256


def _fake_credential(original: str, attempt: int) -> str:
    d = _digest("CREDENTIAL", original, attempt)
    tag = _rand_from(d, string.ascii_uppercase + string.digits, 10)
    return f"[CRED_{tag}]"


def _fake_hash(original: str, attempt: int) -> str:
    d = _digest("HASH", original, attempt)
    return _rand_from(d, "0123456789abcdef", len(original))


def _fake_token(original: str, attempt: int) -> str:
    d = _digest("TOKEN", original, attempt)
    # Preserve well-known prefixes so the model still recognises the kind.
    for prefix in ("ghp_", "gho_", "sk_live_", "sk_test_", "xoxb-", "AKIA", "ASIA"):
        if original.startswith(prefix):
            body = _rand_from(d, _ALNUM, max(8, len(original) - len(prefix)))
            return prefix + body
    tag = _rand_from(d, _ALNUM, 24)
    return f"[TOKEN_{tag}]"


def _fake_mac(original: str, attempt: int) -> str:
    d = _digest("MAC_ADDRESS", original, attempt)
    return ":".join(f"{d[i]:02x}" for i in range(6))


def _fake_path(original: str, attempt: int) -> str:
    d = _digest("PATH", original, attempt)
    return f"/opt/anon/{_rand_from(d, _LOWER, 6)}"


_B64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"


def _fake_b64(original: str, attempt: int) -> str:
    """Same length as the encoded original, base64 alphabet, padding preserved."""
    d = _digest("B64", original, attempt)
    pad = len(original) - len(original.rstrip("="))
    body = _rand_from(d, _B64_ALPHABET.replace("+", "").replace("/", ""),
                      max(1, len(original) - pad))
    return body + ("=" * pad)


def _fake_hex(original: str, attempt: int) -> str:
    d = _digest("HEX", original, attempt)
    return _rand_from(d, "0123456789abcdef", len(original))


_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _fake_b32(original: str, attempt: int) -> str:
    d = _digest("B32", original, attempt)
    pad = len(original) - len(original.rstrip("="))
    body = _rand_from(d, _B32_ALPHABET, max(1, len(original) - pad))
    return body + ("=" * pad)


def _fake_opaque(original: str, attempt: int) -> str:
    """Length-preserving alnum surrogate for structured encodings (url/json)."""
    d = _digest("OPAQUE", original, attempt)
    return _rand_from(d, _ALNUM, max(1, len(original)))


def _is_private_ip(ip: str) -> bool:
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except (ValueError, IndexError):
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


def generate(original: str, entity_type: str, attempt: int = 0) -> str:
    """Return a deterministic surrogate for (original, entity_type, attempt)."""
    if entity_type == "DOMAIN":
        return _fake_domain(original, attempt)
    if entity_type == "HOSTNAME":
        return _fake_hostname(original, attempt)
    if entity_type == "IP_ADDRESS":
        return _fake_ipv4(original, attempt, _is_private_ip(original))
    if entity_type == "CIDR":
        return _fake_cidr(original, attempt, _is_private_ip(original))
    if entity_type in ("EMAIL", "EMAIL_ADDRESS"):
        return _fake_email(original, attempt)
    if entity_type == "USERNAME":
        return _fake_username(original, attempt)
    if entity_type == "PERSON":
        return _fake_person(original, attempt)
    if entity_type == "ORGANIZATION":
        return _fake_org(original, attempt)
    if entity_type == "KEYWORD":
        return _fake_keyword(original, attempt)
    if entity_type == "CREDENTIAL":
        return _fake_credential(original, attempt)
    if entity_type == "HASH":
        return _fake_hash(original, attempt)
    if entity_type == "TOKEN":
        return _fake_token(original, attempt)
    if entity_type == "MAC_ADDRESS":
        return _fake_mac(original, attempt)
    if entity_type == "PATH":
        return _fake_path(original, attempt)
    if entity_type == "ENCODED_B64":
        return _fake_b64(original, attempt)
    if entity_type == "ENCODED_B32":
        return _fake_b32(original, attempt)
    if entity_type == "ENCODED_HEX":
        return _fake_hex(original, attempt)
    if entity_type in ("URL_ENCODED", "JSON_ESCAPED"):
        return _fake_opaque(original, attempt)
    # Fallback
    d = _digest("OTHER", original, attempt)
    return f"[REDACTED_{_rand_from(d, string.ascii_uppercase, 6)}]"
