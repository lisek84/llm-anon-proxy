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
    assert "[CRED_" in anon                # password handled as a credential


def test_p_flag_not_matched_inside_word():
    # The -p credential rule must not fire inside "of-prod-db01".
    anon = anonymizer.anonymize("ssh of_app@of-prod-db01", source="test")
    assert "[CRED_" not in anon
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
