from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses

from app.schemas.email import AttachmentMetadata, EmailAnalysisResponse


def _header(message: Message, name: str) -> str | None:
    value = message.get(name)
    return str(value) if value is not None else None


def _addresses(message: Message, name: str) -> str | None:
    value = _header(message, name)
    if value is None:
        return None
    addresses = getaddresses([value])
    return ", ".join(
        f"{display_name} <{address}>" if display_name else address
        for display_name, address in addresses
    )


def _body_parts(message: Message) -> tuple[str | None, str | None]:
    plain_text: str | None = None
    html: str | None = None

    parts = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True)
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload else ""

        if not isinstance(content, str):
            continue
        if content_type == "text/plain" and plain_text is None:
            plain_text = content
        elif content_type == "text/html" and html is None:
            html = content

    return plain_text, html


def parse_email(raw_email: bytes) -> EmailAnalysisResponse:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    body_text, body_html = _body_parts(message)
    attachments: list[AttachmentMetadata] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename is None and part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True)
        attachments.append(
            AttachmentMetadata(
                filename=filename,
                content_type=part.get_content_type(),
                size=len(payload) if payload is not None else 0,
            )
        )

    return EmailAnalysisResponse(
        from_=_addresses(message, "From"),
        to=_addresses(message, "To"),
        cc=_addresses(message, "Cc"),
        bcc=_addresses(message, "Bcc"),
        subject=_header(message, "Subject"),
        date=_header(message, "Date"),
        message_id=_header(message, "Message-ID"),
        reply_to=_addresses(message, "Reply-To"),
        return_path=_header(message, "Return-Path"),
        mime_version=_header(message, "MIME-Version"),
        content_type=_header(message, "Content-Type"),
        received=[str(value) for value in message.get_all("Received", [])],
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
    )
