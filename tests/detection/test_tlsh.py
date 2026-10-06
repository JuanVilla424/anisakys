"""TLSH port: digests and distances must match the C++ reference (py-tlsh 4.5.0).

The expected values were computed with the reference build (``pip install
python-tlsh==4.5.0`` in a ``python:3.12`` container) on the inputs generated below.
"""

import time

import pytest

from src.detection.tlsh import tlsh_distance, tlsh_hash


def _lcg(n: int, seed: int) -> bytes:
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (1103515245 * x + 12345) % (2**31)
        out.append((x >> 16) & 0xFF)
    return bytes(out)


_HTML = (
    b"<!doctype html><html><head><title>Banco - Inicia sesion</title>"
    b"<link rel='icon' href='/favicon.ico'></head><body><form action='https://api.telegram.org/bot1/x' "
    b"method='post'><input name='usuario'><input type='password' name='clave'>"
    b"<button>Ingresar</button></form><script>var a=atob('aGVsbG8=');</script></body></html>"
) * 7

INPUTS = {
    "fox": b"The quick brown fox jumps over the lazy dog. " * 20,
    "range": bytes(range(256)) * 4,
    "lcg5000": _lcg(5000, 7),
    "lcg300": _lcg(300, 42),
    "lcg50": _lcg(50, 3),
    "lcg49": _lcg(49, 3),
    "html": _HTML,
    "html_edit": _HTML.replace(b"Banco", b"Bank0").replace(b"clave", b"pass"),
    "constant": b"A" * 1000,
}

REFERENCE = {
    "fox": "T16811024A311C1794658A1888438D95B2D2C9C910612114116570604219482359CD8551",
    "range": "T16D119524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D",
    "lcg5000": "T17EA18E3260D5C57924C8D1FC13762F1AD438B71B6391882B90EB9F19E67FE0B8A67161",
    "lcg300": "T168E0721B412422C0D46B8CA60EAF5031C03EB08090FA50A0AAA1824B1A5C68DB3A464A",
    "lcg50": "T1099002D763125A14A48D455161E5602564826918D664681D34C00913A3088D4665402A",
    "lcg49": None,  # shorter than 50 bytes
    "html": "T1D7417DE30804C1086760295198D7B168CD8C9450BD4F9C407DCBBEBA685426D09F5B8A",
    "html_edit": "T1EA417DE20940C108A760296198E7B568CD8C94547D4E9C007CDBBEBA685427D09F6B8A",
    "constant": None,  # too uniform: every quartile is zero
}

REFERENCE_DISTANCES = {
    ("fox", "html"): 337,
    ("fox", "html_edit"): 337,
    ("fox", "lcg300"): 261,
    ("fox", "lcg50"): 240,
    ("fox", "lcg5000"): 446,
    ("fox", "range"): 270,
    ("html_edit", "lcg300"): 316,
    ("html_edit", "lcg50"): 430,
    ("html_edit", "lcg5000"): 285,
    ("html_edit", "range"): 355,
    ("html", "html_edit"): 17,
    ("html", "lcg300"): 309,
    ("html", "lcg50"): 436,
    ("html", "lcg5000"): 296,
    ("html", "range"): 362,
    ("lcg300", "lcg50"): 294,
    ("lcg300", "lcg5000"): 402,
    ("lcg300", "range"): 301,
    ("lcg5000", "range"): 403,
    ("lcg50", "lcg5000"): 520,
    ("lcg50", "range"): 388,
}


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_digests_match_the_reference(name):
    assert tlsh_hash(INPUTS[name]) == REFERENCE[name]


@pytest.mark.parametrize("pair", sorted(REFERENCE_DISTANCES))
def test_distances_match_the_reference(pair):
    first, second = (REFERENCE[name] for name in pair)
    assert first is not None and second is not None

    assert tlsh_distance(first, second) == REFERENCE_DISTANCES[pair]
    assert tlsh_distance(second, first) == REFERENCE_DISTANCES[pair]


def test_an_edited_page_is_near_and_the_digest_is_its_own_zero():
    assert tlsh_distance(REFERENCE["html"], REFERENCE["html"]) == 0
    assert tlsh_distance(REFERENCE["html"], REFERENCE["html_edit"]) < 50


def test_the_prefix_is_optional_and_case_does_not_matter():
    digest = REFERENCE["html"]
    assert digest is not None
    assert tlsh_distance(digest[2:].lower(), digest) == 0


def test_malformed_digests_are_rejected():
    with pytest.raises(ValueError):
        tlsh_distance("T1ABCD", "T1ABCD")


def test_a_large_document_hashes_quickly():
    started = time.monotonic()
    digest = tlsh_hash(bytes(range(256)) * 8192)  # 2 MiB

    assert digest is not None and digest.startswith("T1") and len(digest) == 72
    assert time.monotonic() - started < 5
