"""The abuse report templates and the MIME message built from them.

The old template hard-coded Colombian FCM/SIMIT brand text and URL keyword
"indicators" into every report, called automated reports "manual", claimed
ICANN obligations that do not exist ("2 business days", binding hosting
providers), never rendered threat level/confidence/evidence, linked the live
phishing URL and had no text/plain part.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting.message_builder import (
    TEMPLATES_DIR,
    build_email,
    build_evidence,
    defang_url,
    render_followup,
    render_initial_report,
)

URL = "https://secure-login.bank-example.com/verify/index.php?id=1"
REPORT_ID = "ANISAKYS-20261003-0A1B2C3D"
RESULTS = {
    "aggregated_threat_level": "critical",
    "confidence_score": 93,
    "virustotal": {"malicious": 7, "total_engines": 70},
    "phishtank": {"is_phishing": True, "verified": True},
    "recommendations": ["\U0001f6a8 CRITICAL: URL verified as phishing by PhishTank community"],
}


def _evidence(**overrides):
    values = dict(
        origin="automated",
        brand_name="Example Bank",
        multi_api_results=RESULTS,
        resolved_ip="192.0.2.44",
        asn="AS64500",
        hosting_provider="Example Hosting <b>Ltd</b>",
        registrar="Example Registrar",
        whois_text="Registrar: Example Registrar\nNote: <script>alert(1)</script>",
        attachments=["/tmp/screenshot.png"],
    )
    values.update(overrides)
    return build_evidence(URL, **values)


def _render(**overrides):
    return render_initial_report(
        _evidence(**overrides),
        report_id=REPORT_ID,
        report_time=datetime(2026, 10, 3, 12, 30, tzinfo=timezone.utc),
        subject_base="Phishing report",
        organization="Example CERT",
        followup_hours=48,
    )


def _has_emoji(value: str) -> bool:
    return any(unicodedata.category(char) == "So" for char in value)


def test_templates_carry_no_hard_coded_brand_or_campaign_text():
    for template in Path(TEMPLATES_DIR).glob("*"):
        content = template.read_text(encoding="utf-8").lower()
        for banned in ("fcm", "simit", "colombia", "comparendo", "gov.co", "manual"):
            assert banned not in content, f"{banned!r} in {template.name}"
        assert "2 business days" not in content
        assert not _has_emoji(content), template.name


def test_renders_threat_level_confidence_and_key_evidence():
    rendered = _render()

    for body in (rendered.text, rendered.html):
        assert "CRITICAL" in body
        assert "93%" in body
        assert "VirusTotal: 7 of 70 engines" in body
        assert "PhishTank: verified phishing" in body
        assert "AS64500" in body
        assert "Example Registrar" in body
        assert "2026-10-03 12:30 UTC" in body
        assert "Example Bank" in body


def test_url_is_defanged_and_never_a_link():
    rendered = _render()

    assert defang_url(URL) == "hxxps://secure-login[.]bank-example[.]com/verify/index.php?id=1"
    for body in (rendered.text, rendered.html, rendered.subject):
        assert "bank-example.com" not in body
        assert "https://" not in body
    assert defang_url(URL) in rendered.text
    assert "<a " not in rendered.html.lower()
    assert "192[.]0[.]2[.]44" in rendered.html


def test_registration_data_is_escaped_in_html():
    html = _render().html

    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Example Hosting &lt;b&gt;Ltd&lt;/b&gt;" in html


def test_subject_carries_the_report_id_and_no_emoji():
    subject = _render().subject

    assert subject.startswith(f"[{REPORT_ID}] ")
    assert not _has_emoji(subject)
    assert not _has_emoji(_render().text + _render().html)


@pytest.mark.parametrize(
    "origin, wording", [("automated", "automatically"), ("analyst", "analyst")]
)
def test_origin_wording(origin, wording):
    assert wording in _render(origin=origin).text


def test_brand_may_be_empty():
    rendered = _render(brand_name=None, multi_api_results=None)

    assert "impersonating" not in rendered.text
    assert "Threat level" not in rendered.text


def test_followup_repeats_report_id_and_evidence():
    rendered = render_followup(
        _evidence(),
        report_id=REPORT_ID,
        followup_seq=2,
        original_report_time=datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc),
        check_time=datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc),
        subject_base="Phishing report",
        organization="Example CERT",
        escalation_contacts=["escalation@cert.example"],
    )

    assert rendered.subject.startswith(f"[{REPORT_ID}] Follow-up 2:")
    assert "2026-10-01 09:00 UTC" in rendered.text
    assert "VirusTotal: 7 of 70 engines" in rendered.text
    assert "escalation@cert.example" in rendered.html


def test_message_is_multipart_alternative_with_plain_text_first(tmp_path):
    shot = tmp_path / "screenshot.png"
    shot.write_bytes(b"\x89PNG fake")
    rendered = _render()

    message, attached = build_email(
        rendered.to_payload([str(shot)]),
        sender="reports@cert.example",
        to_addrs=["abuse@registrar.example"],
        message_id=f"<{REPORT_ID}.0.1@cert.example>",
    )

    assert message.get_content_type() == "multipart/mixed"
    alternative = next(message.iter_parts())
    assert alternative.get_content_type() == "multipart/alternative"
    assert [part.get_content_type() for part in alternative.iter_parts()] == [
        "text/plain",
        "text/html",
    ]
    assert attached == ["screenshot.png"]
    assert message["Cc"] is None
    assert message["Message-ID"] == f"<{REPORT_ID}.0.1@cert.example>"
    assert re.search(r"\[ANISAKYS-\d{8}-[0-9A-F]{8}\]", message["Subject"])
