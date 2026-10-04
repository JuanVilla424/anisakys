"""Tests for src.utils.redaction.redact_secrets."""

import pytest

from src.utils.redaction import redact_secrets


@pytest.mark.parametrize(
    "raw, secret",
    [
        ("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSECRET", "AIzaSECRET"),
        ("/x?url=a&app_key=PTSECRET&format=json", "PTSECRET"),
        ("Max retries exceeded with url: /v1/host/x?apikey=S3CR3T", "S3CR3T"),
        ("{'X-Goog-Api-Key': 'AIzaHEADER'}", "AIzaHEADER"),
        ("x-apikey: VTSECRET", "VTSECRET"),
        ("Authorization: Bearer ya29.TOKEN", "ya29.TOKEN"),
        ("https://user:hunter2@example.com/path", "hunter2"),
    ],
)
def test_secrets_are_redacted(raw, secret):
    out = redact_secrets(raw)
    assert secret not in out
    assert "REDACTED" in out


def test_plain_text_is_unchanged():
    text = "GET https://example.com/login?next=/home returned 404"
    assert redact_secrets(text) == text


def test_accepts_exceptions():
    err = ValueError("failed for https://api.example.com/?key=ABC")
    assert "ABC" not in redact_secrets(err)
