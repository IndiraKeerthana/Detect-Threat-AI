import asyncio

from fastapi import APIRouter, File, HTTPException, Response, UploadFile, status

from app.config import get_settings
from app.schemas.email import EmailAnalysisResponse
from app.services.email_parser import parse_email
from app.services.relay_analyzer import analyze_received_headers
from app.services.security_analysis import analyze_security
from app.services.threat_intelligence import analyze_threat_intelligence
from app.services.investigation import analyze_investigation
from app.services.ai_agent.agent import run_ai_investigation
from app.services.pdf_report_generator import generate_forensic_pdf

from app.services.case_storage import save_case
import random
from datetime import datetime, timezone

router = APIRouter()


@router.post("/emails/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(file: UploadFile = File(...)) -> EmailAnalysisResponse:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An .eml email file is required.",
        )

    settings = get_settings()
    max_size_mb = settings.max_email_size_mb
    max_size = int(max_size_mb * 1024 * 1024)
    chunks: list[bytes] = []
    total_size = 0
    while chunk := await file.read(min(64 * 1024, max_size + 1 - total_size)):
        total_size += len(chunk)
        if total_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"The uploaded email file exceeds the {max_size_mb:g} MB limit.",
            )
        chunks.append(chunk)
    raw_email = b"".join(chunks)
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
    relay_analysis = analyze_received_headers(parsed_email.received)
    security_analysis = analyze_security(parsed_email)
    threat_intelligence = analyze_threat_intelligence(
        parsed_email, relay_analysis, security_analysis
    )
    investigation = analyze_investigation(
        parsed_email, security_analysis, threat_intelligence
    )
    try:
        ai_investigation = await asyncio.to_thread(
            run_ai_investigation,
            parsed_email,
            security_analysis,
            threat_intelligence,
            investigation,
            settings=settings,
        )
    except Exception:
        # Step 7 is additive and must never make the established analysis fail.
        ai_investigation = None
    response_obj = parsed_email.model_copy(
        update={
            "relay_analysis": relay_analysis,
            "security_analysis": security_analysis,
            "threat_intelligence": threat_intelligence,
            "correlations": investigation.correlations,
            "evidence_graph": investigation.evidence_graph,
            "risk_assessment": investigation.risk_assessment,
            "confidence": investigation.risk_assessment.confidence,
            "attribution": investigation.attribution,
            "attribution_limitations": investigation.attribution.limitations,
            "recommended_actions": investigation.recommended_actions,
            "investigation_summary": investigation.investigation_summary,
            "investigation": investigation,
            "ai_investigation": ai_investigation,
        }
    )

    try:
        random_suffix = random.randint(1000, 9999)
        case_id = f"CASE-2026-{random_suffix}"
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        raw_sev = (investigation.risk_assessment.level or "high").upper()
        severity = "LOW"
        if "CRIT" in raw_sev:
            severity = "CRITICAL"
        elif "HIGH" in raw_sev:
            severity = "HIGH"
        elif "MED" in raw_sev:
            severity = "MEDIUM"

        subject = response_obj.subject or file.filename or "Suspicious Email Ingestion"
        case_record = {
            "id": case_id,
            "title": f"Forensic Ingestion — {subject}",
            "subject": subject,
            "sender": response_obj.from_ or "Unknown Sender",
            "recipient": response_obj.to or "Undisclosed Recipients",
            "severity": severity,
            "classification": investigation.risk_assessment.classification or "unclassified",
            "riskScore": investigation.risk_assessment.score,
            "confidence": investigation.risk_assessment.confidence.level,
            "status": "OPEN",
            "createdAt": now_str,
            "updatedAt": now_str,
            "sourceIp": (relay_analysis.probable_source_infrastructure.address or "Unavailable") if relay_analysis and relay_analysis.probable_source_infrastructure else "Unavailable",
            "investigationData": response_obj.model_dump(by_alias=True),
        }
        save_case(case_record)
    except Exception:
        pass

    return response_obj



@router.post("/emails/report/pdf")
async def generate_report_pdf(payload: EmailAnalysisResponse, case_id: str = "CASE-UNASSIGNED") -> Response:
    """Generate a downloadable PDF forensic report from an existing EmailAnalysisResponse payload."""
    data_dict = payload.model_dump(by_alias=True)
    pdf_bytes = generate_forensic_pdf(data_dict, case_id=case_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="Forensic_Investigation_Report_{case_id}.pdf"'
        },
    )
