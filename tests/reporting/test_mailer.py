"""The single SMTP path: TLS before credentials, never credentials in clear.

Follow-ups used a bare smtplib.SMTP connection without TLS or login, and the
report path logged in without STARTTLS, which either fails on submission
ports or sends the password in clear text.
"""

from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting.mailer import SmtpConfig, SmtpMailer, SmtpSecurityError


def _message() -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = "s"
    message.set_content("body")
    return message


def _server(starttls: bool) -> MagicMock:
    server = MagicMock()
    server.has_extn.side_effect = lambda name: starttls and name.lower() == "starttls"
    server.sendmail.return_value = {}
    return server


def _config(**overrides) -> SmtpConfig:
    values = dict(
        host="smtp.test.invalid",
        port=587,
        sender="reports@test.invalid",
        user="user",
        password="s3cret",
        security="auto",
    )
    values.update(overrides)
    return SmtpConfig(**values)


def _send(config: SmtpConfig, server: MagicMock, ssl_server: MagicMock = None):
    with (
        patch("src.reporting.mailer.smtplib.SMTP") as smtp,
        patch("src.reporting.mailer.smtplib.SMTP_SSL") as smtp_ssl,
    ):
        smtp.return_value.__enter__.return_value = server
        smtp_ssl.return_value.__enter__.return_value = ssl_server or server
        refused = SmtpMailer(config).send(_message(), ["abuse@desk.invalid"])
    return smtp, smtp_ssl, refused


def test_starttls_happens_before_login():
    server = _server(starttls=True)

    _send(_config(), server)

    calls = [call[0] for call in server.method_calls]
    assert calls.index("starttls") < calls.index("login")
    server.login.assert_called_once_with("user", "s3cret")
    server.sendmail.assert_called_once()


def test_credentials_are_never_sent_without_tls():
    server = _server(starttls=False)

    with pytest.raises(SmtpSecurityError):
        _send(_config(), server)

    server.login.assert_not_called()
    server.sendmail.assert_not_called()


def test_required_starttls_fails_when_not_offered():
    server = _server(starttls=False)

    with pytest.raises(SmtpSecurityError):
        _send(_config(security="starttls", user=None, password=None), server)


def test_port_465_uses_implicit_tls():
    server = _server(starttls=False)

    smtp, smtp_ssl, _ = _send(_config(port=465), server)

    smtp_ssl.assert_called_once()
    smtp.assert_not_called()
    server.starttls.assert_not_called()
    server.login.assert_called_once()


def test_security_none_is_an_explicit_opt_out():
    server = _server(starttls=True)

    _send(_config(security="none"), server)

    server.starttls.assert_not_called()
    server.login.assert_called_once()


def test_partially_refused_recipients_are_returned():
    server = _server(starttls=True)
    server.sendmail.return_value = {"cc@desk.invalid": (550, b"no such user")}

    _, _, refused = _send(_config(user=None, password=None), server)

    assert refused == {"cc@desk.invalid": (550, b"no such user")}


def test_secret_str_password_is_unwrapped(monkeypatch):
    from pydantic import SecretStr

    from src.config import settings

    monkeypatch.setattr(settings, "SMTP_PASS", SecretStr("hidden"))
    monkeypatch.setattr(settings, "SMTP_USER", "user")

    assert SmtpConfig.from_settings().password == "hidden"
