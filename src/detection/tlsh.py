"""TLSH (Trend Micro Locality Sensitive Hash), standard variant: 128 buckets, 1-byte checksum.

A port of the reference implementation (github.com/trendmicro/tlsh, ``tlsh_impl.cpp`` and
``tlsh_util.cpp``) to Python and numpy, so the image needs no C++ toolchain: ``py-tlsh``
ships no wheels for CPython 3.12. Digests are byte-compatible with the reference (the
``T1…`` strings VirusTotal and other tools print); ``tests/detection/test_tlsh.py``
checks them against vectors computed with the C++ build.

Used to compare HTML documents of phishing pages: a distance below ~50 usually means
the same kit or template.
"""

from __future__ import annotations

from bisect import bisect_left
from typing import Optional, Tuple

import numpy as np

# Pearson's sample random table (tlsh_impl.cpp: v_table).
_V = np.array(
    [
        1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
        14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
        110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
        25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
        97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
        174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
        132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
        119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
        138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
        170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
        125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
        118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
        27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
        233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
        140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
        51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
    ],
    dtype=np.uint8,
)  # fmt: skip

# Length-capturing table (tlsh_util.cpp: topval), log-scale buckets of the input length.
_TOPVAL = (
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876,
    2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916,
    10907, 11998, 13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121,
    34233, 37656, 41422, 45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672,
    107439, 118183, 130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337, 278670,
    306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800, 795081,
    874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388, 1704327, 1874759, 2062236,
    2268459, 2495305, 2744836, 3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905,
    5883796, 6472176, 7119394, 7831333, 8614467, 9475909, 10423501, 11465851, 12612437,
    13873681, 15261050, 16787154, 18465870, 20312458, 22343706, 24578077, 27035886,
    29739474, 32713425, 35984770, 39583245, 43541573, 47895730, 52685306, 57953837,
    63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659, 124229227,
    136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671, 266296456,
    292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559, 570830240,
    627913311, 690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880,
    1223623232, 1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648,
    2384496256, 2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
)  # fmt: skip

MIN_DATA_LENGTH = 50
EFF_BUCKETS = 128
CODE_SIZE = 32  # 128 buckets x 2 bits
# Salted Pearson start values (v_table[salt] for salts 2, 3, 5, 7, 11, 13) and the triplet
# each one hashes: (current byte, and two of the previous four).
_TRIPLETS = ((49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4))
_LENGTH_MULT = 12
_QRATIO_MULT = 12


def _pairbit_diff_table() -> np.ndarray:
    """``bit_pairs_diff_table``: distance between two code bytes (four 2-bit buckets).

    Returns:
        A 256x256 table; a bucket difference of 1, 2 or 3 costs 1, 2 or 6.
    """
    cost = (0, 1, 2, 6)
    table = np.zeros((256, 256), dtype=np.int32)
    for x in range(256):
        for y in range(256):
            table[x, y] = sum(cost[abs(((x >> s) & 3) - ((y >> s) & 3))] for s in (0, 2, 4, 6))
    return table


_PAIR_DIFF = _pairbit_diff_table()


def _swap_nibbles(value: int) -> int:
    return ((value & 0xF0) >> 4) | ((value & 0x0F) << 4)


def _l_capturing(length: int) -> int:
    return min(bisect_left(_TOPVAL, length), len(_TOPVAL) - 1)


def _mod_diff(x: int, y: int, ring: int) -> int:
    near = abs(x - y)
    return min(near, ring - near)


def tlsh_hash(data: bytes) -> Optional[str]:
    """TLSH digest of ``data``.

    Args:
        data: Input bytes.

    Returns:
        ``T1`` + 70 hex digits, or ``None`` when the input is too short (< 50 bytes) or too
        uniform to hash (the reference prints ``TNULL``).
    """
    if len(data) < MIN_DATA_LENGTH:
        return None
    buf = np.frombuffer(data, dtype=np.uint8)
    window = [buf[4 - back : len(buf) - back] for back in range(5)]  # current, previous 1..4
    buckets = np.zeros(256, dtype=np.int64)
    for salt, a, b in _TRIPLETS:
        index = _V[_V[_V[salt ^ window[0]] ^ window[a]] ^ window[b]]
        buckets += np.bincount(index, minlength=256)
    # The checksum is a sequential Pearson chain over (current, previous, checksum).
    partial = _V[_V[1 ^ window[0]] ^ window[1]].tobytes()
    table = _V.tobytes()
    checksum = 0
    for value in partial:
        checksum = table[value ^ checksum]

    counts = buckets[:EFF_BUCKETS]
    ordered = np.sort(counts)
    q1, q2, q3 = int(ordered[31]), int(ordered[63]), int(ordered[95])
    if q3 == 0 or int(np.count_nonzero(counts)) <= EFF_BUCKETS // 2:
        return None
    levels = np.where(counts > q3, 3, np.where(counts > q2, 2, np.where(counts > q1, 1, 0)))
    code = [
        int(levels[4 * i] | (levels[4 * i + 1] << 2) | (levels[4 * i + 2] << 4))
        | int(levels[4 * i + 3] << 6)
        for i in range(CODE_SIZE)
    ]
    q1_ratio = int(float(q1 * 100) / float(q3)) % 16
    q2_ratio = int(float(q2 * 100) / float(q3)) % 16
    header = (
        _swap_nibbles(checksum),
        _swap_nibbles(_l_capturing(len(data))),
        _swap_nibbles(q1_ratio | (q2_ratio << 4)),
    )
    return "T1" + bytes(header + tuple(reversed(code))).hex().upper()


def _parse(digest: str) -> Tuple[int, int, int, int, np.ndarray]:
    """Split a digest into checksum, length value, quartile ratios and code.

    Args:
        digest: ``T1`` + 70 hex digits (the ``T1`` prefix is optional).

    Returns:
        ``(checksum, lvalue, q1_ratio, q2_ratio, code)``.

    Raises:
        ValueError: When the digest is malformed.
    """
    text = digest[2:] if digest.upper().startswith("T1") else digest
    raw = bytes.fromhex(text)
    if len(raw) != 3 + CODE_SIZE:
        raise ValueError(f"not a 128-bucket TLSH digest: {digest!r}")
    qb = _swap_nibbles(raw[2])
    code = np.frombuffer(raw[3:], dtype=np.uint8)[::-1]
    return _swap_nibbles(raw[0]), _swap_nibbles(raw[1]), qb & 0x0F, qb >> 4, code


def tlsh_distance(first: str, second: str, include_length: bool = True) -> int:
    """Reference TLSH distance (``totalDiff``): 0 = identical, larger = less similar.

    Args:
        first: Digest.
        second: Digest.
        include_length: Count the difference in input length (reference default).

    Returns:
        The distance.
    """
    c1, l1, a1, b1, code1 = _parse(first)
    c2, l2, a2, b2, code2 = _parse(second)
    diff = 0
    if include_length:
        ldiff = _mod_diff(l1, l2, 256)
        diff = ldiff if ldiff <= 1 else ldiff * _LENGTH_MULT
    for x, y in ((a1, a2), (b1, b2)):
        qdiff = _mod_diff(x, y, 16)
        diff += qdiff if qdiff <= 1 else (qdiff - 1) * _QRATIO_MULT
    if c1 != c2:
        diff += 1
    diff += int(_PAIR_DIFF[code1, code2].sum())
    return diff
