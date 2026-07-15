from dataclasses import dataclass


@dataclass(frozen=True)
class EmailAttachment:
    filename: str
    content: bytes
    content_type: str


@dataclass(frozen=True)
class EmailMessageData:
    subject: str
    text_body: str
    html_body: str | None
    recipients: tuple[str, ...]
    attachments: tuple[EmailAttachment, ...]


@dataclass(frozen=True)
class EmailSendResult:
    recipient_count: int
    attachment_count: int
    message_id: str | None
