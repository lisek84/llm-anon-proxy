"""
Polish national identifiers (PESEL / NIP / REGON): checksum validation, gated
detection (bare PESEL/REGON-14 vs context-only NIP/REGON-9), and valid+inert
surrogates. Valid samples are generated deterministically with the fake_*
builders so no real PESEL/NIP ever appears in the repo.
"""
import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="anonproxy-plid-")
os.environ.setdefault("ANONPROXY_DATA_DIR", _TMP)

from anonproxy import plid, regex_detector, surrogates  # noqa: E402
from anonproxy.config import config  # noqa: E402

_SEED = bytes(range(32))
PESEL = plid.fake_pesel(_SEED)
NIP = plid.fake_nip(_SEED)
REGON9 = plid.fake_regon9(_SEED)
REGON14 = plid.fake_regon14(_SEED)


def test_validators_accept_valid_reject_mutated():
    for val, fn in [(PESEL, plid.valid_pesel), (NIP, plid.valid_nip),
                    (REGON9, plid.valid_regon), (REGON14, plid.valid_regon)]:
        assert fn(val)
        bad = str((int(val[-1]) + 1) % 10)              # break the check digit
        assert not fn(val[:-1] + bad)
    assert not plid.valid_pesel("00000000000")          # all-zero fails the date
    assert not plid.valid_nip("1234567890")             # arbitrary 10 digits
    assert not plid.valid_regon("123456789")


def test_fakes_are_valid_and_digit_only():
    assert plid.valid_pesel(PESEL) and PESEL.isdigit() and len(PESEL) == 11
    assert plid.valid_nip(NIP) and NIP.isdigit() and len(NIP) == 10
    assert plid.valid_regon(REGON9) and REGON9.isdigit() and len(REGON9) == 9
    assert plid.valid_regon(REGON14) and REGON14.isdigit() and len(REGON14) == 14


def _types(text):
    return {t for _, t in regex_detector.detect(text)}


def test_default_detection(monkeypatch):
    monkeypatch.setattr(config, "DETECT_PL_ID", True)
    monkeypatch.setattr(config, "DETECT_PL_ID_BARE", False)
    assert "PESEL" in _types(f"obywatel {PESEL} zapisany")       # bare PESEL
    assert "REGON" in _types(f"firma {REGON14} aktywna")         # bare REGON-14
    assert "NIP" in _types(f"NIP: {NIP}")                        # keyword
    assert "NIP" in _types(f"faktura PL{NIP}")                   # EU VAT
    assert "REGON" in _types(f"REGON {REGON9}")                  # keyword
    # bare NIP / REGON-9 are NOT flagged by default (timestamp/phone collision)
    assert _types(f"kod {NIP} tutaj") == set()
    assert _types(f"id {REGON9} end") == set()


def test_bare_flag_enables_bare_nip_regon(monkeypatch):
    monkeypatch.setattr(config, "DETECT_PL_ID", True)
    monkeypatch.setattr(config, "DETECT_PL_ID_BARE", True)
    assert "NIP" in _types(f"kod {NIP} tutaj")
    assert "REGON" in _types(f"id {REGON9} end")


def test_toggle_off_disables_all(monkeypatch):
    monkeypatch.setattr(config, "DETECT_PL_ID", False)
    assert _types(f"obywatel {PESEL}") == set()
    assert _types(f"NIP: {NIP}") == set()


def test_invalid_eleven_digits_not_pesel(monkeypatch):
    monkeypatch.setattr(config, "DETECT_PL_ID", True)
    # a 13-digit ms timestamp has no 11-digit \b…\b match; an invalid 11-digit run
    # fails validation
    assert "PESEL" not in _types("ts 1700000000000 ms")
    assert "PESEL" not in _types("value 12345678901 here")      # fails checksum/date


def test_surrogate_valid_and_inert():
    for val, t, vfn in [(PESEL, "PESEL", plid.valid_pesel), (NIP, "NIP", plid.valid_nip),
                        (REGON9, "REGON", plid.valid_regon), (REGON14, "REGON", plid.valid_regon)]:
        sur = surrogates.generate(val, t)
        assert sur.isdigit() and len(sur) == len(val)           # same shape, digits only
        assert vfn(sur)                                         # a plausible valid id
        assert sur != val                                       # actually changed
