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
import ipaddress
import os
import stat
import string

from . import plid

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


# Common multi-label public suffixes, so acme.co.uk / shop.acme.co.uk share a base
# (we don't ship the full Public Suffix List; this covers the frequent cases).
_CCTLD_SUFFIX = frozenset((
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "waw.pl",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.kr", "or.kr",
    "co.nz", "org.nz", "govt.nz", "co.za", "org.za", "co.in", "net.in", "org.in",
    "com.br", "com.cn", "com.tr", "com.mx", "com.ar", "com.sg", "com.hk", "com.ua",
))

# SaaS / hosting public suffixes where the LEFTMOST label is a tenant identity
# (your GitHub Pages user, Azure site, Heroku app, …) — often a company/client
# name. Treating them as public suffixes folds that label INTO the surrogated
# base, so `acmecorp.github.io` becomes `<base>.example` instead of leaking
# `acmecorp` as a preserved subdomain under the default "preserve" policy.
# (Deeper multi-level cases like bucket.s3.amazonaws.com aren't covered by this
# last-two-labels scheme; put those in the dictionary if they matter to you.)
_SAAS_SUFFIX = frozenset((
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "r2.dev",
    "azurewebsites.net", "cloudfront.net", "herokuapp.com",
    "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "onrender.com", "fly.dev", "ngrok.io", "ngrok.app", "trycloudflare.com",
))

_MULTI_SUFFIX = _CCTLD_SUFFIX | _SAAS_SUFFIX


def _registrable(host: str) -> str:
    """The registrable (base) domain: example.com, acme.co.uk — last 2 labels,
    or 3 when the last two form a known multi-label public suffix."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _fake_domain(original: str, attempt: int) -> str:
    # Swap only the registrable part; keep sub-labels so a site and its
    # subdomains map consistently (sklep.pl -> ab-cd.example,
    # www.sklep.pl -> www.ab-cd.example, status.sklep.pl -> status.ab-cd.example).
    # The digest is keyed on the base alone, so every subdomain shares one base.
    host = original.lower().strip(".")
    base = _registrable(host)
    sub = host[: len(host) - len(base)].rstrip(".")   # labels before the base, or ""
    d = _digest("DOMAIN", base, attempt)
    label1 = _rand_from(d, _LOWER, 6)
    label2 = _rand_from(d[8:], _LOWER, 5)
    base_surrogate = f"{label1}-{label2}.example"
    if not sub:
        return base_surrogate
    if config.SUBDOMAIN_POLICY == "mask":
        # Replace each sub-label with a deterministic inert token (keyed on the
        # base too, so the same name on different sites isn't linkable), keeping
        # the level structure and the shared base.
        sub = ".".join(_mask_label(base, lbl) for lbl in sub.split("."))
    return f"{sub}.{base_surrogate}"


def _mask_label(base: str, label: str) -> str:
    # Fixed length (not len(label)) so the surrogate leaks neither the name nor
    # its length — a short "vpn" and a long "prod-db01" both map to 8 chars.
    d = _digest("SUBLABEL", f"{base}|{label}", 0)
    return _rand_from(d, _LOWER_DIGITS, 8)


def _fake_hostname(original: str, attempt: int) -> str:
    # 6 alphanumerics (~2 billion values) so collisions stay rare with many hosts.
    d = _digest("HOSTNAME", original, attempt)
    return "host-" + _rand_from(d, string.ascii_lowercase + string.digits, 6)


def _fake_ipv4(original: str, attempt: int, private: bool) -> str:
    d = _digest("IP_ADDRESS", original, attempt)
    if private:
        return f"10.{d[0]}.{d[1]}.{1 + d[2] % 254}"
    # 198.18.0.0/15 — reserved for benchmarking, never routed publicly.
    second = 18 + (d[0] % 2)
    return f"198.{second}.{d[1]}.{1 + d[2] % 254}"


def _fake_cidr(original: str, attempt: int, private: bool) -> str:
    try:
        prefix = int(original.split("/")[-1])
    except ValueError:
        prefix = 24
    base = _fake_ipv4(original, attempt, private)   # in 198.18.0.0/15 or 10.0.0.0/8
    # Same guard as IPv6: masking to a prefix wider than the reserved space would
    # escape it (a /8 base -> 198.0.0.0/8). Never emit a network wider than the
    # reserved prefix (/15 public, /8 private); normalize so no host bits remain.
    floor = 8 if private else 15
    eff = min(max(prefix, floor), 32)
    net = ipaddress.ip_network(f"{base}/{eff}", strict=False)
    return f"{net.network_address}/{eff}"


def _fake_ipv6(original: str, attempt: int, private: bool) -> str:
    d = _digest("IP_ADDRESS6", original, attempt)
    hx = [f"{(d[i] << 8) | d[i + 1]:x}" for i in range(0, 14, 2)]   # 7 hextets of entropy
    if private:
        # ULA fd00::/8 — unmistakably private, never globally routed.
        raw = "fd00:" + ":".join(hx[:6]) + f":{1 + d[14] % 0xfffe:x}"
    else:
        # 2001:db8::/32 — RFC 3849 documentation prefix, never routed.
        raw = "2001:db8:" + ":".join(hx[:5]) + f":{1 + d[14] % 0xfffe:x}"
    return str(ipaddress.IPv6Address(raw))     # canonical/compressed form


def _fake_ipv6_cidr(original: str, attempt: int, private: bool) -> str:
    try:
        prefix = int(original.split("/")[-1])
    except ValueError:
        prefix = 64
    base = _fake_ipv6(original, attempt, private)   # inside 2001:db8::/32 or fd00::/8
    # Masking to a prefix SHORTER than the reserved space would zero out the
    # reserved bits and escape it (/16 -> 2001::/16, a real global range). Never
    # emit a network wider than the reserved prefix: clamp up to its boundary
    # (32 for the doc prefix, 8 for ULA). Longer prefixes stay inside untouched.
    floor = 8 if private else 32
    eff = min(max(prefix, floor), 128)
    net = ipaddress.ip_network(f"{base}/{eff}", strict=False)
    return f"{net.network_address}/{eff}"


def _is_private_ip6(ip: str) -> bool:
    try:
        return ipaddress.IPv6Address(ip.split("/")[0]).is_private
    except ValueError:
        return False


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
    return f"CRED-{tag}"   # no brackets: keep every surrogate shell/glob-inert


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
    return f"TOKEN-{tag}"   # no brackets: keep every surrogate shell/glob-inert


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
        if ":" in original:
            return _fake_ipv6(original, attempt, _is_private_ip6(original))
        return _fake_ipv4(original, attempt, _is_private_ip(original))
    if entity_type == "CIDR":
        if ":" in original:
            return _fake_ipv6_cidr(original, attempt, _is_private_ip6(original))
        return _fake_cidr(original, attempt, _is_private_ip(original))
    if entity_type == "PESEL":
        return plid.fake_pesel(_digest("PESEL", original, attempt))
    if entity_type == "NIP":
        return plid.fake_nip(_digest("NIP", original, attempt))
    if entity_type == "REGON":
        dig = _digest("REGON", original, attempt)
        return plid.fake_regon14(dig) if len(original) == 14 else plid.fake_regon9(dig)
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
