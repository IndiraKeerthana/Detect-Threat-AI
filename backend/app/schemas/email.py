from pydantic import BaseModel, ConfigDict, Field


class AttachmentMetadata(BaseModel):
    filename: str | None
    content_type: str
    size: int


class EmailAnalysisResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: str | None = Field(alias="from")
    to: str | None
    cc: str | None
    bcc: str | None
    subject: str | None
    date: str | None
    message_id: str | None
    reply_to: str | None
    return_path: str | None
    mime_version: str | None
    content_type: str | None
    received: list[str]
    body_text: str | None
    body_html: str | None
    attachments: list[AttachmentMetadata]
