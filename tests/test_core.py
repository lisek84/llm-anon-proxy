"""
Round-trip and leak tests. These mirror the failures found in the earlier
review of the reference project, now asserted closed.
"""
import os
import tempfile

import pytest

# Point config at throwaway data before importing modules that read it.
_TMP = tempfile.mkdtemp(prefix="anonproxy-test-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")
os.environ["ANONPROXY_LEAKLOG"] = os.path.join(_TMP, "rotate.jsonl")
os.environ["ANONPROXY_CONTEXT"] = "test"

with open(os.environ["ANONPROXY_DICT"], "w") as f:
    f.write(
        "domains:\n  - example.com\n"
        "hosts:\n  - of-prod-db01\n"
        "ips:\n  - 185.12.34.56\n"
        "usernames:\n  - of_app\n"
        "organizations:\n  - example\n"
        "paths:\n  - /home/lisek/example-ops\n"
    )

from pathlib import Path  # noqa: E402

from anonproxy import vault, dictionary, anonymizer, surrogates  # noqa: E402
from anonproxy.config import config  # noqa: E402


# Capture this module's own paths now — the env vars are shared across test
# modules and get overwritten when another module is imported.
_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]


@pytest.fixture(autouse=True)
def _ctx():
    """Pin this module's context before every test (config is a shared singleton,
    so another test module may have pointed it elsewhere)."""
    config.CONTEXT_ID = "test"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.LLM_ENABLED = False
    config.AUDIT_ENABLED = False
    vault.init()
    dictionary.load()
    yield


def rt(text):
    """Anonymize then deanonymize — should round-trip to the original."""
    anon = anonymizer.anonymize(text, source="test")
    return anon, anonymizer.deanonymize(anon)


# ── Dictionary layer ──────────────────────────────────────────────────────────

def test_domain_and_subdomain_roundtrip():
    anon, back = rt("connect to cdn3.example.com and example.com")
    assert "example.com" not in anon
    assert "cdn3." in anon          # subdomain structure preserved
    assert back == "connect to cdn3.example.com and example.com"


def test_subdomain_surrogates_share_one_base():
    # A site and its subdomains must map to related surrogates, so the model can
    # tell they're the same site (apex surrogate is the shared base).
    apex = surrogates.generate("acme-crm.pl", "DOMAIN")
    assert apex.endswith(".example") and apex.count(".") == 1
    assert surrogates.generate("www.acme-crm.pl", "DOMAIN") == "www." + apex
    assert surrogates.generate("status.acme-crm.pl", "DOMAIN") == "status." + apex
    # a different registrable domain gets a different base
    other = surrogates.generate("www.other-shop.pl", "DOMAIN")
    assert not other.endswith("." + apex)


def test_multi_label_public_suffix_shares_base():
    apex = surrogates.generate("acme.co.uk", "DOMAIN")       # co.uk kept as suffix
    assert surrogates.generate("shop.acme.co.uk", "DOMAIN") == "shop." + apex


def test_subdomain_mask_policy_hides_labels(monkeypatch):
    monkeypatch.setattr(config, "SUBDOMAIN_POLICY", "mask")
    apex = surrogates.generate("acme.pl", "DOMAIN")
    sub = surrogates.generate("prod-db01.acme.pl", "DOMAIN")
    assert "prod-db01" not in sub                    # sensitive label hidden
    assert sub.endswith("." + apex)                  # shared base kept (consistency)
    assert sub.count(".") == apex.count(".") + 1     # one extra level, structure kept
    assert sub == surrogates.generate("prod-db01.acme.pl", "DOMAIN")  # deterministic


def test_pesel_roundtrips_through_pipeline():
    from anonproxy import plid
    pesel = plid.fake_pesel(bytes(range(3, 19)))
    anon, back = rt(f"obywatel {pesel} w rejestrze")
    assert pesel not in anon
    assert back == f"obywatel {pesel} w rejestrze"


def test_subdomain_mask_constant_length(monkeypatch):
    # The masked label must not leak the original name's length.
    monkeypatch.setattr(config, "SUBDOMAIN_POLICY", "mask")
    short = surrogates.generate("vpn.acme.pl", "DOMAIN").split(".")[0]
    long = surrogates.generate("prod-db-server-01.acme.pl", "DOMAIN").split(".")[0]
    assert len(short) == len(long) == 8


def test_llm_safe_filter_rejects_tech_noise_keeps_names():
    safe = anonymizer._llm_is_safe
    # a small model over-flags this technical vocabulary — must be ignored
    for noise in ["WSL-u", "SSH_AUTH_SOCK", "~/.ssh", "~/.ssh/id_rsa", "$SSH_AUTH_SOCK",
                  "llm-anon-proxy_deploy", "SUGGESTION MODE", "HOME", "PATH", "id_rsa",
                  "config.yaml", "-v", "./deploy.sh"]:
        assert safe(noise), f"{noise!r} should be filtered out"
    # real sensitive names must still pass through (not filtered)
    for real in ["BACKUP-NODE-07", "DR-SITE-MUNICH-03", "edge-gw-fra1", "Kowalski",
                 "Fundacja Zielona Przyszlosc"]:
        assert not safe(real), f"{real!r} should NOT be filtered"


def test_git_service_email_not_anonymized():
    from anonproxy import regex_detector
    assert not any(e == "EMAIL" for _, e in regex_detector.detect("push to git@github.com"))


def test_bare_brand_replaced():
    anon, back = rt("deploy aplikacji example na prod")
    assert "example" not in anon
    assert back == "deploy aplikacji example na prod"


def test_path_and_host_and_user():
    anon, back = rt("ssh of_app@of-prod-db01:/home/lisek/example-ops")
    for s in ("of_app", "of-prod-db01", "/home/lisek/example-ops"):
        assert s not in anon
    assert back == "ssh of_app@of-prod-db01:/home/lisek/example-ops"


# ── Regex safety net (the previously-leaking cases) ───────────────────────────

# Token fixtures are assembled from pieces so the committed file contains no
# literal that matches a provider secret-scanner (these are fake, but their
# shape is real on purpose — that is what the regex must catch).
_GHP = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
_SK_LIVE = "sk_" + "live_" + "51HxFAKEFAKEFAKE0123456789abcd"
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.mark.parametrize("text,secret", [
    ("mysql -uroot -pHunter2pass -h db", "Hunter2pass"),
    ("sshpass -p 'Zx9!kLm2' ssh root@srv", "Zx9!kLm2"),
    ("PGPASSWORD=Pg_s3cr3t psql -h db", "Pg_s3cr3t"),
    ("  password: Tr0ub4dor&3", "Tr0ub4dor&3"),
    ("DATABASE_URL=postgres://app:Qw3rty99@db:5432/main", "Qw3rty99"),
    ("Authorization: Bearer abcDEF123456ghiJKL789mnoPQR", "abcDEF123456ghiJKL789mnoPQR"),
    ("admin:$apr1$Kq8x$J7t0Ffakehashvalue12", "$apr1$Kq8x$J7t0Ffakehashvalue12"),
    ("requirepass r3d1sP4ss", "r3d1sP4ss"),
    ("stats auth pgadmin:Haproxy_St4ts!", "Haproxy_St4ts!"),
    ("define( 'DB_PASSWORD', 'wpP4ss_x1' );", "wpP4ss_x1"),
    (f"key is {_GHP}", _GHP),
    (f"STRIPE={_SK_LIVE}", _SK_LIVE),
])
def test_secret_not_leaked(text, secret):
    anon = anonymizer.anonymize(text, source="test")
    assert secret not in anon, f"LEAK: {secret!r} survived in {anon!r}"


def test_encoded_variants_of_dictionary_value_caught():
    import base64
    v = "example.com"  # in the test dictionary
    for enc in (base64.b64encode(v.encode()).decode(),
                base64.b64encode(v.encode()).decode().rstrip("="),
                base64.urlsafe_b64encode(v.encode()).decode(),
                v.encode().hex()):
        anon, back = rt(f"data: {enc}")
        assert enc not in anon, f"encoded form leaked: {enc!r} in {anon!r}"
        assert back == f"data: {enc}"


def test_encoded_boundary_no_partial_match():
    # base64 of a longer string must not be partially scrubbed just because a
    # shorter dictionary value's base64 is a prefix of it.
    import base64
    longer = base64.b64encode(b"exampleXYZ_not_a_domain").decode()
    anon = anonymizer.anonymize(f"blob {longer}", source="test")
    # It should pass through intact (not a declared value), not be half-replaced.
    assert longer in anon


def test_leak_scan_skips_metadata_and_noise():
    from anonproxy import leaklog
    leaklog._seen_hashes.clear()
    body = {
        "metadata": {"user_id": "a" * 64},                 # account id — must be ignored
        "messages": [{"role": "user", "content": "checksum " + "b" * 32}],  # a hash — not rotatable
    }
    assert anonymizer.scan_body_for_leaks(body, "test") == 0
    leaklog._seen_hashes.clear()
    body2 = {"messages": [{"role": "user", "content": f"keys {_AKIA} and {_GHP}"}]}
    assert anonymizer.scan_body_for_leaks(body2, "test") == 2   # both tokens flagged


def test_json_keys_anonymized_and_restored():
    import json as _json
    v = {"example.com": "up", "note": "/home/lisek/example-ops"}
    anon = anonymizer.anonymize_value(v)
    assert "example.com" not in _json.dumps(anon)   # sensitive KEY scrubbed too
    assert anonymizer.deanon_value(anon) == v        # round-trips, keys included


def test_email_with_dictionary_domain_fully_replaced():
    # The local part must not leak when the domain is in the dictionary.
    anon, back = rt("kontakt jan.kowalski@example.com proszę")
    assert "jan.kowalski" not in anon
    assert "example.com" not in anon
    assert back == "kontakt jan.kowalski@example.com proszę"


def test_credential_containing_dictionary_domain_fully_replaced():
    anon, back = rt("password=Tajne.example.com!2024")
    assert "Tajne." not in anon and "!2024" not in anon
    assert "example.com" not in anon
    assert back == "password=Tajne.example.com!2024"


def test_bare_term_not_matched_inside_fresh_surrogate():
    # A bare dictionary word ("example") must not match inside a domain surrogate
    # just inserted (whose TLD is ".example"). Replacement is position-based over
    # the original text, so the round-trip must be exact.
    text = "/srv/example and https://cdn3.example.com/x"
    anon, back = rt(text)
    assert "example.com" not in anon
    assert back == text  # surrogate TLD intact; nothing double-replaced


def test_deanonymize_no_substring_corruption():
    # Surrogate "k9" is a substring of another mapping's original "x-k9-y".
    # Position-based restore must not turn "QQQ" into a double-expanded mess.
    vault.get_or_create("ALPHA", "OTHER", lambda o, e, a: "k9")
    vault.get_or_create("x-k9-y", "OTHER", lambda o, e, a: "QQQ")
    assert anonymizer.deanonymize("run QQQ now") == "run x-k9-y now"
    assert anonymizer.deanonymize("val k9 end") == "val ALPHA end"


def test_person_surrogate_has_no_whitespace():
    s, _ = vault.get_or_create("Jan Kowalski", "PERSON", surrogates.generate)
    assert " " not in s and "\t" not in s and "\n" not in s
    assert anonymizer.deanonymize(s) == "Jan Kowalski"


def test_parse_keeps_hash_inside_values():
    d = dictionary._parse_minimal_yaml('credentials:\n  - "pa#ss"\n  - plain # comment\n')
    assert d["credentials"] == ["pa#ss", "plain"]


def test_user_allowlist_keeps_domain():
    from anonproxy import regex_detector
    regex_detector.set_user_allow(["hetzner.com"])
    try:
        found = {v for v, _ in regex_detector.detect("use hetzner.com and othercorp.com")}
        assert "hetzner.com" not in found
        assert "othercorp.com" in found
    finally:
        regex_detector.set_user_allow([])


def test_ip_not_matched_inside_oid():
    # SNMP OIDs and long dotted-number runs must not yield a bogus IP.
    text = "sysUpTime .1.3.6.1.2.1.1.3.0 = 12345"
    anon = anonymizer.anonymize(text, source="test")
    assert anon == text  # nothing replaced


def test_cctld_two_label_domain_fully_caught():
    anon, back = rt("relay smtp.discoinfinito.com.br now")
    assert "discoinfinito" not in anon and ".com.br" not in anon
    assert back == "relay smtp.discoinfinito.com.br now"


def test_broad_cctld_domain_caught():
    anon = anonymizer.anonymize("see mail.correos.es please", source="test")
    assert "correos.es" not in anon


def test_code_tokens_not_treated_as_domains():
    text = "log.info('x'); import socket.io; self.app.run()"
    anon = anonymizer.anonymize(text, source="test")
    assert "log.info" in anon and "socket.io" in anon and "self.app" in anon


@pytest.mark.parametrize("text,ip", [
    ("Blocked scanner 52.90.38.71.", "52.90.38.71"),
    ("ip=52.90.38.71.", "52.90.38.71"),
    ("Connect to 5.6.7.8. Done", "5.6.7.8"),
])
def test_ip_with_trailing_dot_still_caught(text, ip):
    # N1 regression: a '.' right after the IP must not suppress it.
    assert ip not in anonymizer.anonymize(text, source="test")


def test_ptr_ip_caught_even_with_provider_allowlisted():
    from anonproxy import regex_detector
    regex_detector.set_user_allow(["leaseweb.net"])
    try:
        anon = anonymizer.anonymize("PTR 37.48.100.252.leaseweb.net", source="test")
        assert "37.48.100.252" not in anon      # IP in the PTR name is scrubbed
        assert "leaseweb.net" in anon           # the allowlisted provider stays
    finally:
        regex_detector.set_user_allow([])


def test_filenames_and_code_fields_not_domains():
    # N2 regression: ambiguous TLDs must not swallow file names / code attributes.
    for tok in ("README.md", "deploy.sh", "libssl.so", "user.id", "obj.app",
                "req.id", "notes.ai", "file.it", "x.es", "self.me"):
        anon = anonymizer.anonymize(f"touch {tok} here", source="test")
        assert tok in anon, f"{tok} wrongly anonymized -> {anon}"


@pytest.mark.parametrize("text,token", [
    ("deploy.sh:12: echo x", "deploy.sh"),
    ("README.md:3:# Title", "README.md"),
    ("./install.sh: line 5: foo: command not found", "install.sh"),
])
def test_grep_file_line_not_treated_as_domain(text, token):
    # N5: file:line: in grep/bash output must not look like host.tld:port
    assert token in anonymizer.anonymize(text, source="test")


@pytest.mark.parametrize("text", ["host.io:8080", "host.io:8080/x"])
def test_ambiguous_tld_with_real_port_is_caught(text):
    assert "host.io" not in anonymizer.anonymize(text, source="test")


def test_ambiguous_tld_caught_with_three_labels_or_netctx():
    # …but a real domain on an ambiguous TLD is still caught with 3 labels or ctx.
    assert "api.service.ai" not in anonymizer.anonymize("call api.service.ai now", source="test")
    assert "db.corp.io" not in anonymizer.anonymize("mysql://db.corp.io:3306/x", source="test")


def test_dsn_password_is_credential_not_email():
    # N3: proto://user:pass@host — password is a CREDENTIAL, host keeps subdomain.
    text = "DATABASE_URL=https://admin:S3cr3tPASS@db.bigfirm.com/x"
    anon = anonymizer.anonymize(text, source="test")
    assert "S3cr3tPASS" not in anon        # password gone
    assert "db.bigfirm.com" not in anon    # host anonymized
    assert "CRED-" in anon                # password handled as a credential


def test_surrogates_are_shell_inert():
    # A surrogate may reach a shell/path if the model mangles it past the
    # restorer, so NO surrogate may contain a character that changes a command's
    # meaning (expansion $, command subst `, separators ; | &, redirection < >,
    # globs * ? [ ], quotes, whitespace, backslash). Allowed: [A-Za-z0-9._@:/=-].
    import re as _re
    allowed = _re.compile(r"^[A-Za-z0-9._@:/=-]+$")
    cases = [
        ("DOMAIN", ["example.com", "www.acme-crm.pl", "a.b.c.example.co.uk"]),
        ("HOSTNAME", ["prod-db01", "x"]),
        ("IP_ADDRESS", ["51.75.1.2", "2a01:4f8:1c1c:abcd::5", "fd00:1234:5::9"]),
        ("CIDR", ["51.75.0.0/16", "10.9.0.0/8", "2a01:4f8::/48", "fc00::/7"]),
        ("EMAIL", ["admin@jesiotr.pl"]),
        ("USERNAME", ["deploy", "jan.kowalski"]),
        ("PERSON", ["Jan Kowalski", "Łukasz Żółć"]),
        ("ORGANIZATION", ["Acme Corp S.A."]),
        ("KEYWORD", ["secret-project!", "$weird; name"]),
        ("CREDENTIAL", ["Hunter2pass", "Tr0ub4dor&3", "p@ss$word"]),
        ("HASH", ["deadbeef" * 4]),
        ("TOKEN", ["ghp_" + "A" * 36, "sk_live_" + "x" * 24, "random-looking-token-123456"]),
        ("MAC_ADDRESS", ["aa:bb:cc:dd:ee:ff"]),
        ("PATH", ["/var/www/secret", "/opt/$HOME/../etc"]),
        ("PESEL", [surrogates.plid.fake_pesel(bytes(range(16)))]),
        ("NIP", [surrogates.plid.fake_nip(bytes(range(16)))]),
        ("REGON", [surrogates.plid.fake_regon9(bytes(range(16))),
                   surrogates.plid.fake_regon14(bytes(range(16)))]),
    ]
    for etype, originals in cases:
        for original in originals:
            for attempt in range(3):          # collision retries must stay inert too
                sur = surrogates.generate(original, etype, attempt)
                assert allowed.match(sur), f"{etype} surrogate {sur!r} has an active char"
                assert not (set(sur) & set("$`;|&<>()*?[]'\" \t\n\\")), \
                    f"{etype} surrogate {sur!r} contains a shell metacharacter"


def test_p_flag_not_matched_inside_word():
    # The -p credential rule must not fire inside "of-prod-db01".
    anon = anonymizer.anonymize("ssh of_app@of-prod-db01", source="test")
    assert "CRED-" not in anon
    assert "of-prod-db01" not in anon  # still replaced as a hostname


def test_private_key_block():
    pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA\n"
           "-----END OPENSSH PRIVATE KEY-----")
    anon = anonymizer.anonymize(pem, source="test")
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA" not in anon


# ── Determinism / no collisions across "restarts" ─────────────────────────────

def test_no_surrogate_collisions_many_ips():
    originals = [f"185.12.{i}.{j}" for i in range(20) for j in range(1, 13)]
    surs = {}
    for ip in originals:
        s, _ = vault.get_or_create(ip, "IP_ADDRESS", surrogates.generate)
        surs[ip] = s
    # Every surrogate unique, and each reverse-maps to exactly its own original.
    assert len(set(surs.values())) == len(originals)
    for ip, s in surs.items():
        assert anonymizer.deanonymize(s) == ip


def test_surrogate_stable_across_reload():
    s1, _ = vault.get_or_create("91.200.7.7", "IP_ADDRESS", surrogates.generate)
    vault.init()  # simulate restart
    s2, _ = vault.get_or_create("91.200.7.7", "IP_ADDRESS", surrogates.generate)
    assert s1 == s2


# ── Allowlist: tooling domains/IPs stay intact ────────────────────────────────

def test_outgoing_scan_flags_missed_secret_not_surrogate():
    import json as _json
    from anonproxy import leaklog
    # A surrogate ghp_ token must NOT be flagged as a leak.
    anon = anonymizer.anonymize(f"token {_GHP}", source="test")
    assert anonymizer.scan_for_leaks(anon, "test") == 0
    # But a raw secret embedded in otherwise-anonymized text IS flagged.
    leaklog._seen_hashes.clear()
    assert anonymizer.scan_for_leaks(f"leftover {_AKIA}", "test") == 1


def test_allowlist_kept():
    text = "pip install from pypi.org, api at api.anthropic.com, dns 8.8.8.8"
    anon = anonymizer.anonymize(text, source="test")
    assert "pypi.org" in anon
    assert "anthropic.com" in anon
    assert "8.8.8.8" in anon


def test_llm_safe_terms_filtered():
    # Tool/protocol/platform terms and CVEs from the LLM layer are ignored.
    llm = [("nmap", "ORGANIZATION"), ("smb", "HOSTNAME"), ("CVE-2024-6387", "ORGANIZATION"),
           ("kube-system", "ORGANIZATION"), ("web-prod-01", "HOSTNAME")]
    text = "nmap smb CVE-2024-6387 kube-system web-prod-01"
    anon = anonymizer.anonymize(text, llm_matches=llm, source="test")
    for kept in ("nmap", "smb", "CVE-2024-6387", "kube-system"):
        assert kept in anon
    assert "web-prod-01" not in anon  # a real hostname is still replaced


def test_slack_webhook_token_caught():
    url = "https://hooks.slack.com/services/T000ABC/B111DEF/xoxbFAKE0123456789"
    anon = anonymizer.anonymize(f"webhook: {url}", source="test")
    assert "xoxbFAKE0123456789" not in anon


@pytest.mark.parametrize("d", ["docker.io", "ghcr.io", "quay.io", "docs.google.com",
                               "proxy.golang.org", "registry.k8s.io", "crates.io"])
def test_common_dev_domains_not_anonymized(d):
    # These fill Claude Code's own system prompt and are not user infrastructure.
    assert d in anonymizer.anonymize(f"pull from {d} now", source="t")


def test_risky_dictionary_literal_flagged():
    assert dictionary._is_risky_literal("user")
    assert dictionary._is_risky_literal("db")
    assert dictionary._is_risky_literal("api")
    assert not dictionary._is_risky_literal("acme-crm.pl")
    assert not dictionary._is_risky_literal("db-prod-01")


# ── IPv6 ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,ip", [
    ("server at 2a01:4f8:1c1c:abcd::5 up", "2a01:4f8:1c1c:abcd::5"),
    ("ula fd00:1234:5::9 host", "fd00:1234:5::9"),
    ("link fe80::1ff:fe23:4567:890a nic", "fe80::1ff:fe23:4567:890a"),
    ("full 2a01:4f8:1c1c:abcd:0:0:0:5 ok", "2a01:4f8:1c1c:abcd:0:0:0:5"),
    ("mapped ::ffff:203.0.113.9 x", "::ffff:203.0.113.9"),
])
def test_ipv6_detected_and_roundtrips(text, ip):
    anon, back = rt(text)
    assert ip not in anon
    assert back == text


def test_ipv6_cidr_detected_and_roundtrips():
    anon, back = rt("route fd00:1234::/48 via gw")
    assert "fd00:1234::/48" not in anon
    assert "/48" in anon                 # prefix length preserved
    assert back == "route fd00:1234::/48 via gw"


def test_ipv6_surrogate_ranges():
    # global → documentation prefix 2001:db8::/32; private (ULA/link-local) → fd00::/8
    import ipaddress
    glob = ipaddress.ip_address(surrogates.generate("2a01:4f8:1c1c:abcd::5", "IP_ADDRESS"))
    priv = ipaddress.ip_address(surrogates.generate("fd00:1234:5::9", "IP_ADDRESS"))
    assert glob in ipaddress.ip_network("2001:db8::/32")
    assert priv.is_private


@pytest.mark.parametrize("orig,reserved", [
    ("51.75.0.0/8", "198.18.0.0/15"),     # public, wider than /15 — must clamp
    ("51.75.0.0/16", "198.18.0.0/15"),
    ("51.75.1.0/24", "198.18.0.0/15"),
    ("51.75.1.9/32", "198.18.0.0/15"),
    ("10.9.0.0/8", "10.0.0.0/8"),         # private
    ("172.16.0.0/12", "10.0.0.0/8"),
])
def test_ipv4_cidr_surrogate_stays_in_reserved_space(orig, reserved):
    import ipaddress
    net = ipaddress.ip_network(surrogates.generate(orig, "CIDR"))
    assert net.subnet_of(ipaddress.ip_network(reserved)), f"{orig} -> {net} escaped {reserved}"


@pytest.mark.parametrize("orig,reserved", [
    ("2a01:4f8::/16", "2001:db8::/32"),   # wider than the doc prefix — must clamp, not escape
    ("2a01:4f8::/24", "2001:db8::/32"),
    ("2a01:4f8::/32", "2001:db8::/32"),
    ("2a01:4f8:1::/48", "2001:db8::/32"),
    ("2a01:4f8:1::/64", "2001:db8::/32"),
    ("fc00::/7", "fd00::/8"),             # wider than ULA fd00::/8 — must clamp
    ("fd12:3456::/32", "fd00::/8"),
])
def test_ipv6_cidr_surrogate_stays_in_reserved_space(orig, reserved):
    import ipaddress
    net = ipaddress.ip_network(surrogates.generate(orig, "CIDR"))
    assert net.subnet_of(ipaddress.ip_network(reserved)), f"{orig} -> {net} escaped {reserved}"


@pytest.mark.parametrize("text", [
    "loopback ::1 only",
    "google dns 2001:4860:4860::8888 resolver",
    "mac aa:bb:cc:dd:ee:ff is not an ip",
    "time 12:34:56 is not an ip",
])
def test_ipv6_allowlist_and_false_positives_not_anonymized_as_ip(text):
    # ::1 and public resolvers are allowlisted; MAC/time must not become an IP.
    got = {t: ty for t, ty in __import__("anonproxy.regex_detector",
                                         fromlist=["detect"]).detect(text)}
    assert "::1" not in got and "2001:4860:4860::8888" not in got
    assert got.get("aa:bb:cc:dd:ee:ff") in (None, "MAC_ADDRESS")
    assert "12:34:56" not in got
