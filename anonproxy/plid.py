"""
Polish national identifiers: PESEL, NIP, REGON.

Each is a plain digit string with a checksum (PESEL also encodes a birth date),
so a candidate run of digits is *validated* before it is treated as an id — this
is what keeps the false-positive rate low enough to be useful (see the benchmark
notes in the review). Validators are used by the regex detector; the fake_*
builders produce deterministic, checksum-VALID surrogates (digits only, so they
stay shell-inert and are never re-flagged as a leak).
"""

_PESEL_W = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
_NIP_W = (6, 5, 7, 2, 3, 4, 5, 6, 7)
_REGON9_W = (8, 9, 2, 3, 4, 5, 6, 7)
_REGON14_W = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)


def _d(s: str) -> list[int]:
    return [int(c) for c in s]


def valid_pesel(s: str) -> bool:
    if len(s) != 11 or not s.isdigit():
        return False
    d = _d(s)
    ctrl = (10 - (sum(w * x for w, x in zip(_PESEL_W, d[:10])) % 10)) % 10
    if ctrl != d[10]:
        return False
    mm, dd = d[2] * 10 + d[3], d[4] * 10 + d[5]
    month_ok = (1 <= mm <= 12 or 21 <= mm <= 32 or 41 <= mm <= 52
                or 61 <= mm <= 72 or 81 <= mm <= 92)
    return month_ok and 1 <= dd <= 31


def valid_nip(s: str) -> bool:
    if len(s) != 10 or not s.isdigit():
        return False
    d = _d(s)
    ctrl = sum(w * x for w, x in zip(_NIP_W, d[:9])) % 11
    return ctrl != 10 and ctrl == d[9]


def valid_regon(s: str) -> bool:
    if not s.isdigit():
        return False
    if len(s) == 9:
        d = _d(s)
        return sum(w * x for w, x in zip(_REGON9_W, d[:8])) % 11 % 10 == d[8]
    if len(s) == 14:
        d = _d(s)
        ctrl = sum(w * x for w, x in zip(_REGON14_W, d[:13])) % 11 % 10
        return ctrl == d[13] and valid_regon(s[:9])
    return False


# ── deterministic, checksum-valid fakes (fed an HMAC digest from surrogates) ────

def fake_pesel(dig: bytes) -> str:
    yy, mm, dd = dig[0] % 100, 1 + dig[1] % 12, 1 + dig[2] % 28
    body = [yy // 10, yy % 10, mm // 10, mm % 10, dd // 10, dd % 10,
            dig[3] % 10, dig[4] % 10, dig[5] % 10, dig[6] % 10]
    ctrl = (10 - (sum(w * x for w, x in zip(_PESEL_W, body)) % 10)) % 10
    return "".join(map(str, body + [ctrl]))


def fake_nip(dig: bytes) -> str:
    d = [dig[i] % 10 for i in range(9)]
    ctrl = sum(w * x for w, x in zip(_NIP_W, d)) % 11
    if ctrl == 10:                      # 10 is not a legal NIP check digit — nudge one
        d[0] = (d[0] + 1) % 10
        ctrl = sum(w * x for w, x in zip(_NIP_W, d)) % 11
    return "".join(map(str, d)) + str(ctrl)


def fake_regon9(dig: bytes) -> str:
    d = [dig[i] % 10 for i in range(8)]
    ctrl = sum(w * x for w, x in zip(_REGON9_W, d)) % 11 % 10
    return "".join(map(str, d)) + str(ctrl)


def fake_regon14(dig: bytes) -> str:
    d = _d(fake_regon9(dig)) + [dig[9 + i] % 10 for i in range(4)]   # 13 digits
    ctrl = sum(w * x for w, x in zip(_REGON14_W, d)) % 11 % 10
    return "".join(map(str, d)) + str(ctrl)
