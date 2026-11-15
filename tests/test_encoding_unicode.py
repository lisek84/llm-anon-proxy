"""
Unicode normalization and encoded-form coverage for dictionary values,
using a non-ASCII (Polish) name — the "user named Łukasz" case.
"""
import base64
import json
import os
import tempfile
import unicodedata
import urllib.parse
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-enc-")
os.environ["ANONPROXY_DATA_DIR"] = _TMP
os.environ["ANONPROXY_DB"] = os.path.join(_TMP, "t.db")
os.environ["ANONPROXY_DICT"] = os.path.join(_TMP, "dict.yaml")

with open(os.environ["ANONPROXY_DICT"], "w", encoding="utf-8") as f:
    f.write('persons:\n  - "Łukasz Kowalski"\n'
            'domains:\n  - kraków-prod.example-firma.pl\n')

from anonproxy import vault, dictionary, anonymizer  # noqa: E402
from anonproxy.config import config  # noqa: E402

_MY_DB = os.environ["ANONPROXY_DB"]
_MY_DICT = os.environ["ANONPROXY_DICT"]
NAME = "Łukasz Kowalski"


@pytest.fixture(autouse=True)
def _ctx():
    config.CONTEXT_ID = "enctest"
    config.DB_PATH = Path(_MY_DB)
    config.DICT_PATH = Path(_MY_DICT)
    config.AUDIT_ENABLED = False
    config.LLM_ENABLED = False
    vault.init()
    dictionary.load()
    yield


def _anon(text):
    a = anonymizer.anonymize(text, source="test")
    return a, anonymizer.deanonymize(a)


def test_plain_nfc_and_nfd_both_match():
    anon_nfc, _ = _anon("user " + unicodedata.normalize("NFC", NAME))
    anon_nfd, _ = _anon("user " + unicodedata.normalize("NFD", NAME))
    assert NAME not in anon_nfc
    # NFD input must be caught too (normalized before matching).
    assert unicodedata.normalize("NFD", NAME) not in anon_nfd
    assert NAME not in anon_nfd


@pytest.mark.parametrize("make", [
    lambda v: ("SECRET=", base64.b64encode(v.encode()).decode()),           # KEY=<b64>
    lambda v: ("tok ",   base64.b64encode(v.encode()).decode().rstrip("=")),
    lambda v: ("x ",     base64.urlsafe_b64encode(v.encode()).decode()),
    lambda v: ("x ",     base64.b32encode(v.encode()).decode()),
    lambda v: ("val=",   v.encode().hex()),
    lambda v: ("val=",   v.encode().hex().upper()),
    lambda v: ("q=",     urllib.parse.quote(v, safe="")),
    lambda v: ("n=",     json.dumps(v)[1:-1]),
])
def test_encoded_forms_scrubbed_and_roundtrip(make):
    pre, enc = make(NAME)
    text = pre + enc
    anon, back = _anon(text)
    assert enc not in anon, f"encoded form leaked: {enc!r} in {anon!r}"
    assert back == text


def test_base64_prefix_not_partially_matched():
    # base64 of a longer unknown string sharing a prefix with the name's base64
    # must pass through untouched (no misleading partial scrub).
    longer = base64.b64encode((NAME + "_and_more_text").encode()).decode()
    anon = anonymizer.anonymize("blob " + longer, source="test")
    assert longer in anon
