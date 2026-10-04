"""The single SMTP sending path for abuse reports, follow-ups and test reports.

Transport security follows ``SMTP_SECURITY``:

* ``ssl`` — implicit TLS (``SMTP_SSL``), the usual setup on port 465.
* ``starttls`` — plain connection upgraded with STARTTLS; fails if the server
  does not offer it.
* ``auto`` (default) — ``ssl`` on port 465, otherwise STARTTLS whenever the
  server offers it.
* ``none`` — never negotiate TLS (loopback relays only).

Credentials (``SMTP_USER``/``SMTP_PASS``) are only sent over TLS unless the
operator chose ``none`` explicitly. Certificates are verified with the system
trust store. Neither the password nor message bodies are logged.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Dict, Optional, Sequence, Tuple


from src.config import settings, secret_value
from src.logger import logger


class SmtpSecurityError(smtplib.SMTPException):
    """The connection cannot be secured as ``SMTP_SECURITY`` requires."""


@dataclass(frozen=True)
class SmtpConfig:
    """Connection settings for the outbound relay."""

    host: str
    port: int
    sender: str
    user: Optional[str] = None
    password: Optional[str] = None
    security: str = "auto"
    timeout: int = 30

    @classmethod
    def from_settings(cls) -> "SmtpConfig":
        """Read the relay configuration from ``src.config.settings``.

        Returns:
            The configuration (``SMTP_PASS`` may be a plain string or a
            ``SecretStr``).
        """
        password = secret_value(getattr(settings, "SMTP_PASS", None))
        return cls(
            host=settings.SMTP_HOST,
            port=int(settings.SMTP_PORT),
            sender=settings.ABUSE_EMAIL_SENDER,
            user=getattr(settings, "SMTP_USER", None) or None,
            password=password or None,
            security=getattr(settings, "SMTP_SECURITY", "auto"),
            timeout=int(getattr(settings, "SMTP_TIMEOUT_SECONDS", 30)),
        )


class SmtpMailer:
    """Send one message per call over a freshly opened, secured connection."""

    def __init__(self, config: Optional[SmtpConfig] = None) -> None:
        """Create a mailer.

        Args:
            config: Fixed configuration; when ``None`` the settings are read at
                every send, so runtime overrides take effect.
        """
        self._config = config

    @property
    def config(self) -> SmtpConfig:
        """Effective relay configuration.

        Returns:
            The fixed configuration or the one read from settings now.
        """
        return self._config or SmtpConfig.from_settings()

    def send(self, message: EmailMessage, recipients: Sequence[str]) -> Dict[str, Tuple]:
        """Deliver ``message`` to ``recipients`` (the SMTP envelope).

        Args:
            message: Fully built message.
            recipients: Envelope recipients.

        Returns:
            Recipients the server refused while accepting others (empty when
            all were accepted).

        Raises:
            SmtpSecurityError: TLS is required but unavailable, or credentials
                would be sent in clear text.
            smtplib.SMTPException: Any SMTP-level failure, including every
                recipient being refused.
            OSError: Connection-level failures (DNS, refused, timeout).
        """
        config = self.config
        security = config.security
        if security == "auto" and config.port == 465:
            security = "ssl"
        context = ssl.create_default_context()

        if security == "ssl":
            client = smtplib.SMTP_SSL(
                config.host, config.port, timeout=config.timeout, context=context
            )
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=config.timeout)

        with client as server:
            server.ehlo()
            secured = security == "ssl"
            if security in ("starttls", "auto"):
                if server.has_extn("starttls"):
                    server.starttls(context=context)
                    server.ehlo()
                    secured = True
                elif security == "starttls":
                    raise SmtpSecurityError("SMTP server does not offer STARTTLS")
            if config.user and config.password:
                if not secured and security != "none":
                    raise SmtpSecurityError(
                        "Refusing to send SMTP credentials over an unencrypted connection"
                    )
                server.login(config.user, config.password)
            refused = server.sendmail(config.sender, list(recipients), message.as_bytes())

        refused = refused if isinstance(refused, dict) else {}
        logger.info(
            f"SMTP accepted message for {len(recipients) - len(refused)} of "
            f"{len(recipients)} recipient(s) via {config.host}:{config.port}"
        )
        return refused
