import re
import smtplib
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from loguru import logger

from notifications.models import EmailMessageData, EmailSendResult


EMAIL_PATTERN = re.compile(r"^[^@\s,<>]+@[^@\s,<>]+\.[^@\s,<>]+$")


class SmtpEmailSender:
    def __init__(
        self,
        smtp_host: str | None,
        smtp_port: int = 587,
        smtp_username: str | None = None,
        smtp_password: str | None = None,
        smtp_from_address: str | None = None,
        smtp_from_name: str = "Security Intelligence Assistant",
        smtp_use_tls: bool = True,
        smtp_use_ssl: bool = False,
        smtp_timeout_seconds: float = 30.0,
        smtp_factory: Callable[..., object] = smtplib.SMTP,
        smtp_ssl_factory: Callable[..., object] = smtplib.SMTP_SSL,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_from_address = smtp_from_address
        self.smtp_from_name = smtp_from_name
        self.smtp_use_tls = smtp_use_tls
        self.smtp_use_ssl = smtp_use_ssl
        self.smtp_timeout_seconds = smtp_timeout_seconds
        self.smtp_factory = smtp_factory
        self.smtp_ssl_factory = smtp_ssl_factory

    def send(self, message_data: EmailMessageData) -> EmailSendResult:
        recipients = validate_recipients(message_data.recipients)
        self.validate(recipients=recipients, require_password=True)
        message = self.build_message(message_data, recipients)

        logger.info(
            "Sending report email: "
            f"smtp_host={self.smtp_host}, "
            f"recipient_count={len(recipients)}, "
            f"attachment_count={len(message_data.attachments)}"
        )
        smtp = self._connect()
        with smtp as server:
            if self.smtp_use_tls:
                server.ehlo()
                server.starttls()
                server.ehlo()
            if self.smtp_username:
                server.login(self.smtp_username, self.smtp_password or "")
            server.send_message(message)

        return EmailSendResult(
            recipient_count=len(recipients),
            attachment_count=len(message_data.attachments),
            message_id=message["Message-ID"],
        )

    def validate(
        self,
        recipients: tuple[str, ...],
        require_password: bool = True,
    ) -> None:
        if not self.smtp_host:
            raise ValueError("smtp_host is required")
        if not self.smtp_from_address:
            raise ValueError("smtp_from_address is required")
        validate_email_address(self.smtp_from_address)
        if not recipients:
            raise ValueError("at least one recipient is required")
        if self.smtp_use_tls and self.smtp_use_ssl:
            raise ValueError("smtp_use_tls and smtp_use_ssl cannot both be true")
        if self.smtp_password and not self.smtp_username:
            raise ValueError("smtp_password requires smtp_username")
        if require_password and self.smtp_username and not self.smtp_password:
            raise ValueError("smtp_password is required when smtp_username is configured")

    def build_message(
        self,
        message_data: EmailMessageData,
        recipients: tuple[str, ...] | None = None,
    ) -> EmailMessage:
        normalized_recipients = recipients or validate_recipients(message_data.recipients)
        message = EmailMessage()
        message["Subject"] = message_data.subject
        message["From"] = formataddr((self.smtp_from_name, self.smtp_from_address or ""))
        message["To"] = ", ".join(normalized_recipients)
        message["Message-ID"] = make_msgid()
        message.set_content(message_data.text_body, subtype="plain", charset="utf-8")
        if message_data.html_body is not None:
            message.add_alternative(message_data.html_body, subtype="html", charset="utf-8")

        for attachment in message_data.attachments:
            maintype, subtype = split_content_type(attachment.content_type)
            message.add_attachment(
                attachment.content,
                maintype=maintype,
                subtype=subtype,
                filename=attachment.filename,
            )
        return message

    def _connect(self):
        factory = self.smtp_ssl_factory if self.smtp_use_ssl else self.smtp_factory
        return factory(self.smtp_host, self.smtp_port, timeout=self.smtp_timeout_seconds)


def parse_recipients(value: str) -> tuple[str, ...]:
    return validate_recipients(tuple(part.strip() for part in value.split(",")))


def validate_recipients(values: tuple[str, ...]) -> tuple[str, ...]:
    recipients: list[str] = []
    seen: set[str] = set()
    for value in values:
        address = value.strip()
        if not address:
            continue
        validate_email_address(address)
        key = address.casefold()
        if key not in seen:
            seen.add(key)
            recipients.append(address)
    if not recipients:
        raise ValueError("at least one recipient is required")
    return tuple(recipients)


def validate_email_address(value: str) -> None:
    if not EMAIL_PATTERN.match(value):
        raise ValueError(f"invalid email address: {value}")


def split_content_type(content_type: str) -> tuple[str, str]:
    parts = [part.strip() for part in content_type.split("/")]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"malformed content type: {content_type}")
    return parts[0], parts[1]
