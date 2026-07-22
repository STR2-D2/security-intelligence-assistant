import argparse
import html
import re
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from app.config import settings
from app.logging import setup_logging
from notifications.email import SmtpEmailSender, parse_recipients, validate_recipients
from notifications.models import EmailAttachment, EmailMessageData, EmailSendResult


REPORT_PATTERN = "security_advisory_*.md"
REPORT_DATE_PATTERN = re.compile(r"security_advisory_(\d{4}-\d{2}-\d{2})\.md$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send latest security advisory report by email")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--subject")
    parser.add_argument("--recipient", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def find_newest_report(reports_dir: Path = Path("reports")) -> Path:
    reports = list(reports_dir.glob(REPORT_PATTERN))
    if not reports:
        raise FileNotFoundError(f"No report files found in {reports_dir}")
    return sorted(reports, key=lambda path: (path.stat().st_mtime, path.name))[-1]


def default_subject(report_path: Path, now: datetime | None = None) -> str:
    match = REPORT_DATE_PATTERN.match(report_path.name)
    date_text = match.group(1) if match else (now or datetime.now(UTC)).date().isoformat()
    return f"安全漏洞预警报告 - {date_text}"


def markdown_to_html(markdown: str) -> str:
    lines = ["<html>", "<body>"]
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        escaped = html.escape(line)
        if not line:
            continue
        if line.startswith("### "):
            lines.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("- "):
            lines.append(f"<p>&bull; {html.escape(line[2:])}</p>")
        else:
            lines.append(f"<p>{escaped}</p>")
    lines.extend(["</body>", "</html>"])
    return "\n".join(lines)


def resolve_recipients(
    cli_recipients: list[str],
    configured_recipients: str,
) -> tuple[str, ...]:
    if cli_recipients:
        return validate_recipients(tuple(cli_recipients))
    return parse_recipients(configured_recipients)


def build_email_message(
    report_path: Path,
    subject: str,
    recipients: tuple[str, ...],
) -> EmailMessageData:
    markdown = report_path.read_text(encoding="utf-8")
    if not markdown.strip():
        raise ValueError(f"Report file is empty: {report_path}")
    return EmailMessageData(
        subject=subject,
        text_body=markdown,
        html_body=markdown_to_html(markdown),
        recipients=recipients,
        attachments=(
            EmailAttachment(
                filename=report_path.name,
                content=markdown.encode("utf-8"),
                content_type="text/markdown",
            ),
        ),
    )


def build_sender() -> SmtpEmailSender:
    smtp_settings = settings.resolve_smtp_settings()
    return SmtpEmailSender(
        smtp_host=smtp_settings["smtp_host"],
        smtp_port=smtp_settings["smtp_port"],
        smtp_username=smtp_settings["smtp_username"],
        smtp_password=smtp_settings["smtp_password"],
        smtp_from_address=smtp_settings["smtp_from_address"],
        smtp_from_name=smtp_settings["smtp_from_name"],
        smtp_use_tls=smtp_settings["smtp_use_tls"],
        smtp_use_ssl=smtp_settings["smtp_use_ssl"],
        smtp_timeout_seconds=smtp_settings["smtp_timeout_seconds"],
    )


def send_report(
    report_path: Path | None,
    subject: str | None,
    recipients: tuple[str, ...],
    sender: SmtpEmailSender,
    dry_run: bool = False,
) -> EmailSendResult | None:
    selected_report = report_path or find_newest_report()
    selected_subject = subject or default_subject(selected_report)
    message = build_email_message(selected_report, selected_subject, recipients)

    if dry_run:
        sender.validate(recipients=message.recipients, require_password=False)
        logger.info(
            "Email dry run: "
            f"subject={message.subject}, "
            f"recipient_count={len(message.recipients)}, "
            f"attachment={message.attachments[0].filename}, "
            f"text_body_length={len(message.text_body)}, "
            f"html_body_length={len(message.html_body or '')}"
        )
        return None

    return sender.send(message)


def main() -> None:
    args = parse_args()
    setup_logging(settings.log_level)
    recipients = resolve_recipients(args.recipient, settings.report_email_recipients)
    result = send_report(
        report_path=args.report,
        subject=args.subject,
        recipients=recipients,
        sender=build_sender(),
        dry_run=args.dry_run,
    )
    if result is not None:
        logger.info(
            "Email sent successfully: "
            f"recipient_count={result.recipient_count}, "
            f"attachment_count={result.attachment_count}"
        )


if __name__ == "__main__":
    main()
