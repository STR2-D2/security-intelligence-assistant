import smtplib

import pytest
from loguru import logger

from notifications.email import SmtpEmailSender, parse_recipients
from notifications.models import EmailAttachment, EmailMessageData


class FakeSMTP:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls: list[str] = []
        self.message = None

    def __enter__(self):
        self.calls.append("enter")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.calls.append("exit")

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self) -> None:
        self.calls.append("starttls")

    def login(self, username: str, password: str) -> None:
        self.calls.append(f"login:{username}:{password}")

    def send_message(self, message) -> None:
        self.calls.append("send_message")
        self.message = message


def message(
    recipients: tuple[str, ...] = ("sec@example.com",),
    attachments: tuple[EmailAttachment, ...] = (),
) -> EmailMessageData:
    return EmailMessageData(
        subject="安全报告",
        text_body="中文正文",
        html_body="<p>中文正文</p>",
        recipients=recipients,
        attachments=attachments,
    )


def sender(**overrides):
    instances: list[FakeSMTP] = []

    def factory(host: str, port: int, timeout: float) -> FakeSMTP:
        instance = FakeSMTP(host, port, timeout)
        instances.append(instance)
        return instance

    values = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_username": None,
        "smtp_password": None,
        "smtp_from_address": "sender@example.com",
        "smtp_from_name": "Security Intelligence Assistant",
        "smtp_use_tls": True,
        "smtp_use_ssl": False,
        "smtp_timeout_seconds": 12.0,
        "smtp_factory": factory,
        "smtp_ssl_factory": factory,
    }
    values.update(overrides)
    return SmtpEmailSender(**values), instances


def test_starttls_connection_sequence() -> None:
    email_sender, instances = sender()

    email_sender.send(message())

    assert instances[0].calls == ["enter", "ehlo", "starttls", "ehlo", "send_message", "exit"]


def test_ssl_connection_sequence() -> None:
    email_sender, instances = sender(smtp_use_tls=False, smtp_use_ssl=True, smtp_port=465)

    email_sender.send(message())

    assert instances[0].calls == ["enter", "send_message", "exit"]
    assert instances[0].port == 465


def test_plain_smtp_connection() -> None:
    email_sender, instances = sender(smtp_use_tls=False, smtp_use_ssl=False)

    email_sender.send(message())

    assert instances[0].calls == ["enter", "send_message", "exit"]


def test_login_when_credentials_exist() -> None:
    email_sender, instances = sender(smtp_username="user", smtp_password="secret")

    email_sender.send(message())

    assert "login:user:secret" in instances[0].calls


def test_no_login_without_username() -> None:
    email_sender, instances = sender()

    email_sender.send(message())

    assert all(not call.startswith("login") for call in instances[0].calls)


def test_message_subject_from_and_to() -> None:
    email_sender, instances = sender()

    email_sender.send(message(recipients=("a@example.com", "b@example.com")))
    built = instances[0].message

    assert built["Subject"] == "安全报告"
    assert "sender@example.com" in built["From"]
    assert built["To"] == "a@example.com, b@example.com"
    assert built["Message-ID"]


def test_utf8_chinese_body_and_html_alternative() -> None:
    email_sender, instances = sender()

    email_sender.send(message())
    built = instances[0].message

    assert "中文正文" in built.get_body(preferencelist=("plain",)).get_content()
    assert "中文正文" in built.get_body(preferencelist=("html",)).get_content()


def test_markdown_attachment() -> None:
    attachment = EmailAttachment("report.md", b"# report", "text/markdown")
    email_sender, instances = sender()

    email_sender.send(message(attachments=(attachment,)))
    attachments = list(instances[0].message.iter_attachments())

    assert attachments[0].get_filename() == "report.md"
    assert attachments[0].get_content_type() == "text/markdown"
    assert attachments[0].get_content() == "# report"


def test_malformed_content_type() -> None:
    email_sender, _ = sender()
    attachment = EmailAttachment("report.md", b"report", "markdown")

    with pytest.raises(ValueError, match="malformed content type"):
        email_sender.send(message(attachments=(attachment,)))


@pytest.mark.parametrize(
    ("overrides", "message_text"),
    [
        ({"smtp_host": None}, "smtp_host"),
        ({"smtp_from_address": None}, "smtp_from_address"),
        ({"smtp_use_tls": True, "smtp_use_ssl": True}, "cannot both be true"),
        ({"smtp_username": None, "smtp_password": "secret"}, "smtp_password requires"),
    ],
)
def test_configuration_validation(overrides, message_text: str) -> None:
    email_sender, _ = sender(**overrides)

    with pytest.raises(ValueError, match=message_text):
        email_sender.send(message())


def test_missing_recipients() -> None:
    email_sender, _ = sender()

    with pytest.raises(ValueError, match="at least one recipient"):
        email_sender.send(message(recipients=("",)))


def test_invalid_email_address() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        parse_recipients("valid@example.com, bad-address")


def test_smtp_exception_propagates() -> None:
    class FailingSMTP(FakeSMTP):
        def send_message(self, message) -> None:
            raise smtplib.SMTPException("send failed")

    def factory(host: str, port: int, timeout: float) -> FailingSMTP:
        return FailingSMTP(host, port, timeout)

    email_sender, _ = sender(smtp_factory=factory)

    with pytest.raises(smtplib.SMTPException):
        email_sender.send(message())


def test_password_does_not_appear_in_logs() -> None:
    records: list[str] = []
    sink_id = logger.add(records.append, format="{message}")
    try:
        email_sender, _ = sender(smtp_username="user", smtp_password="super-secret")
        email_sender.send(message())
    finally:
        logger.remove(sink_id)

    assert "super-secret" not in "\n".join(records)
