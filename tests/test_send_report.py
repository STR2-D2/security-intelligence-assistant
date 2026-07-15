from pathlib import Path

import pytest

from app import send_report
from notifications.models import EmailSendResult


class FakeSender:
    def __init__(self) -> None:
        self.sent_message = None
        self.validated = False

    def validate(self, recipients, require_password=True) -> None:
        self.validated = True

    def send(self, message):
        self.sent_message = message
        return EmailSendResult(
            recipient_count=len(message.recipients),
            attachment_count=len(message.attachments),
            message_id="id",
        )


def write_report(path: Path, content: str = "# 报告\n- item") -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_newest_report_selection(tmp_path) -> None:
    older = write_report(tmp_path / "security_advisory_2026-01-01.md")
    newer = write_report(tmp_path / "security_advisory_2026-01-02.md")
    older.touch()
    newer.touch()

    assert send_report.find_newest_report(tmp_path) == newer


def test_explicit_report_selection(tmp_path) -> None:
    explicit = write_report(tmp_path / "custom.md")
    fake_sender = FakeSender()

    send_report.send_report(
        explicit,
        None,
        ("sec@example.com",),
        fake_sender,
    )

    assert fake_sender.sent_message.attachments[0].filename == "custom.md"


def test_default_subject_from_filename(tmp_path) -> None:
    report = tmp_path / "security_advisory_2026-05-06.md"

    assert send_report.default_subject(report) == "安全漏洞预警报告 - 2026-05-06"


def test_explicit_subject(tmp_path) -> None:
    report = write_report(tmp_path / "security_advisory_2026-01-01.md")
    fake_sender = FakeSender()

    send_report.send_report(report, "Custom Subject", ("sec@example.com",), fake_sender)

    assert fake_sender.sent_message.subject == "Custom Subject"


def test_recipient_cli_override() -> None:
    recipients = send_report.resolve_recipients(
        ["cli@example.com"],
        "config@example.com",
    )

    assert recipients == ("cli@example.com",)


def test_configured_recipient_fallback_and_duplicate_removal() -> None:
    recipients = send_report.resolve_recipients(
        [],
        "a@example.com, b@example.com, A@example.com",
    )

    assert recipients == ("a@example.com", "b@example.com")


def test_invalid_recipient_rejection() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        send_report.resolve_recipients(["not-email"], "")


def test_markdown_to_html_escaping() -> None:
    html = send_report.markdown_to_html("# <Title>\n- a & b\nplain <script>")

    assert "<h1>&lt;Title&gt;</h1>" in html
    assert "<p>&bull; a &amp; b</p>" in html
    assert "&lt;script&gt;" in html


def test_dry_run_does_not_connect_to_smtp(tmp_path) -> None:
    report = write_report(tmp_path / "security_advisory_2026-01-01.md")
    fake_sender = FakeSender()

    result = send_report.send_report(
        report,
        None,
        ("sec@example.com",),
        fake_sender,
        dry_run=True,
    )

    assert result is None
    assert fake_sender.validated is True
    assert fake_sender.sent_message is None


def test_missing_report_handling(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        send_report.find_newest_report(tmp_path)


def test_attachment_contents_match_report_file(tmp_path) -> None:
    report = write_report(tmp_path / "security_advisory_2026-01-01.md", "# hello")
    message = send_report.build_email_message(report, "Subject", ("sec@example.com",))

    assert message.attachments[0].content == "# hello".encode("utf-8")


def test_empty_report_is_rejected(tmp_path) -> None:
    report = write_report(tmp_path / "security_advisory_2026-01-01.md", "")

    with pytest.raises(ValueError, match="empty"):
        send_report.build_email_message(report, "Subject", ("sec@example.com",))
