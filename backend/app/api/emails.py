from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.schemas.email import EmailAnalysisResponse
from app.services.email_parser import parse_email
from app.services.relay_analyzer import analyze_received_headers
from app.services.security_analysis import analyze_security

router = APIRouter()


@router.post("/emails/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(file: UploadFile = File(...)) -> EmailAnalysisResponse:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An .eml email file is required.",
        )

    raw_email = await file.read()
    if not raw_email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded email file is empty.",
        )

    try:
        parsed_email = parse_email(raw_email)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is not a valid email.",
        ) from exc

    if (
        not any(parsed_email.model_dump(exclude={"received", "attachments"}).values())
        and not parsed_email.authentication_results
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file does not contain email headers.",
        )
    return parsed_email.model_copy(
        update={
            "relay_analysis": analyze_received_headers(parsed_email.received),
            "security_analysis": analyze_security(parsed_email),
        }
    )
