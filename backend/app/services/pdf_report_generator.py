"""PDF Report Generator for DetectThreatAI.

Generates a professional multi-page cybersecurity forensic PDF report from actual
investigation results returned by the backend engine.
"""

import hashlib
import io
import re
from datetime import datetime, timezone, timedelta
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Colors matching DetectThreatAI modern dark/forensic aesthetic adapted for PDF
COLOR_PRIMARY = colors.HexColor("#0f172a")       # Dark Slate background / headers
COLOR_SECONDARY = colors.HexColor("#06b6d4")     # Cyan accent
COLOR_ACCENT_PURPLE = colors.HexColor("#8b5cf6")  # Purple accent
COLOR_TEXT_DARK = colors.HexColor("#1e293b")      # Dark text
COLOR_TEXT_MUTED = colors.HexColor("#64748b")     # Muted grey text
COLOR_BG_LIGHT = colors.HexColor("#f8fafc")       # Card background
COLOR_BORDER = colors.HexColor("#cbd5e1")         # Table/card border

# Severity Colors
COLOR_CRITICAL = colors.HexColor("#ef4444")
COLOR_HIGH = colors.HexColor("#f97316")
COLOR_MEDIUM = colors.HexColor("#f59e0b")
COLOR_LOW = colors.HexColor("#10b981")
COLOR_INFO = colors.HexColor("#3b82f6")


def sanitize_text(text: Any) -> str:
    """Sanitize strings to prevent secret leakage and HTML breakage in ReportLab."""
    if text is None:
        return "Unavailable"
    s = str(text)
    # Mask API keys and bearer tokens
    s = re.sub(r"gsk_[A-Za-z0-9_-]+", "[REDACTED_API_KEY]", s)
    s = re.sub(r"Bearer\s+[A-Za-z0-9_.-]+", "Bearer [REDACTED_TOKEN]", s)
    s = re.sub(r"sk-[A-Za-z0-9]{20,}", "[REDACTED_SECRET]", s)
    # Escape HTML special chars for ReportLab Paragraphs
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s


def format_ist_timestamp(ts: Any) -> str:
    """Format timestamp into explicit IST presentation string."""
    if not ts or ts in ("Unavailable", "Unrecorded", "None", "null"):
        return "Unavailable"
    if isinstance(ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            return "Unavailable"
    elif isinstance(ts, datetime):
        dt = ts
    else:
        raw_str = str(ts).strip()
        if not raw_str:
            return "Unavailable"
        try:
            dt = datetime.fromisoformat(raw_str.replace("Z", "+00:00"))
        except Exception:
            return sanitize_text(raw_str)
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    dt_ist = dt.astimezone(ist_tz)
    return dt_ist.strftime("%d %b %Y, %I:%M:%S %p IST")


def compute_evidence_hash(data: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 fingerprint for forensic evidence integrity."""
    evidence_str = (
        f"{data.get('from')}|{data.get('to')}|{data.get('subject')}|"
        f"{data.get('message_id')}|{data.get('date')}|{len(data.get('received', []))}"
    )
    return hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()


def generate_forensic_pdf(data_dict: dict[str, Any], case_id: str = "CASE-UNASSIGNED") -> bytes:
    """Generate complete multi-page PDF report from EmailAnalysisResponse dict."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom Paragraph Styles
    style_title = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=COLOR_PRIMARY,
        spaceAfter=4,
    )
    style_subtitle = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_TEXT_MUTED,
        spaceAfter=12,
    )
    style_h2 = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=COLOR_PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    style_body = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=COLOR_TEXT_DARK,
        spaceAfter=6,
    )
    style_body_bold = ParagraphStyle(
        "BodyTextBoldCustom",
        parent=style_body,
        fontName="Helvetica-Bold",
    )
    style_code = ParagraphStyle(
        "CodeCustom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=COLOR_PRIMARY,
        wordWrap="CJK",
    )
    style_table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=COLOR_TEXT_DARK,
        wordWrap="CJK",
    )
    style_table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=style_table_cell,
        fontName="Helvetica-Bold",
    )
    style_table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )
    style_alert_box = ParagraphStyle(
        "AlertBox",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#7c2d12"),
    )

    story = []

    # Extract Data Objects safely
    risk_assessment = data_dict.get("risk_assessment") or {}
    security_analysis = data_dict.get("security_analysis") or {}
    relay_analysis = data_dict.get("relay_analysis") or {}
    threat_intel = data_dict.get("threat_intelligence") or {}
    ai_investigation = data_dict.get("ai_investigation") or {}
    investigation_summary = data_dict.get("investigation_summary") or {}
    attribution = data_dict.get("attribution") or {}
    confidence = data_dict.get("confidence") or {}
    recommended_actions = data_dict.get("recommended_actions") or []

    risk_score = risk_assessment.get("score", 0)
    risk_level = (risk_assessment.get("level") or "low").upper()
    classification = (risk_assessment.get("classification") or "unclassified").upper()
    evidence_sha256 = compute_evidence_hash(data_dict)
    report_gen_time = format_ist_timestamp(datetime.now(timezone.utc))

    # =========================================================================
    # 1. REPORT HEADER
    # =========================================================================
    header_table_data = [
        [
            Paragraph("<b>DetectThreatAI</b> | FORENSIC INVESTIGATION REPORT", style_title),
            Paragraph(f"<b>CASE REF:</b> {sanitize_text(case_id)}", ParagraphStyle("RightHeader", parent=style_code, alignment=2)),
        ],
        [
            Paragraph("Automated &amp; AI-Assisted Email Security Analysis Record (NIST SP 800-86)", style_subtitle),
            Paragraph(f"<b>GENERATED:</b> {report_gen_time}", ParagraphStyle("RightHeaderSub", parent=style_code, alignment=2)),
        ],
    ]
    t_header = Table(header_table_data, colWidths=[4.2 * inch, 3.2 * inch])
    t_header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_header)
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_SECONDARY, spaceBefore=4, spaceAfter=10))

    # Meta Quick Bar Table
    meta_bar = [
        [
            Paragraph("<b>STATUS:</b> OPEN", style_table_cell),
            Paragraph(f"<b>SEVERITY:</b> {risk_level}", style_table_cell),
            Paragraph(f"<b>RISK SCORE:</b> {risk_score}/100", style_table_cell),
            Paragraph(f"<b>CLASSIFICATION:</b> {classification}", style_table_cell),
        ]
    ]
    t_meta = Table(meta_bar, colWidths=[1.85 * inch] * 4)
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 2. EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("1. Executive Summary", style_h2))
    
    rationale_text = risk_assessment.get("rationale") or investigation_summary.get("summary") or "No assessment summary generated."
    primary_reasons = []
    for factor in risk_assessment.get("factors", []):
        primary_reasons.append(f"• <b>{sanitize_text(factor.get('title'))}</b> (+{factor.get('contribution', 0)} pts): {sanitize_text(factor.get('explanation'))}")
    
    exec_summary_html = (
        f"This email artifact (Subject: <i>{sanitize_text(data_dict.get('subject') or '(No Subject)')}</i>) was evaluated with a total risk score of "
        f"<b>{risk_score}/100</b> ({risk_level} severity, classified as <b>{classification}</b>).<br/><br/>"
        f"<b>Verdict Synthesis:</b> {sanitize_text(rationale_text)}"
    )
    story.append(Paragraph(exec_summary_html, style_body))
    
    if primary_reasons:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Primary Contributing Factors:</b>", style_body_bold))
        for r in primary_reasons:
            story.append(Paragraph(r, style_body))
    
    story.append(Spacer(1, 8))

    # =========================================================================
    # 3. EMAIL DETAILS
    # =========================================================================
    story.append(Paragraph("2. Email Metadata &amp; Headers", style_h2))
    attachments = data_dict.get("attachments") or []
    attach_desc = ", ".join([f"{sanitize_text(a.get('filename'))} ({a.get('size', 0)} bytes)" for a in attachments]) if attachments else "None"

    email_details_data = [
        [Paragraph("<b>Header Field</b>", style_table_header), Paragraph("<b>Extracted Value</b>", style_table_header)],
        [Paragraph("From Sender", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("from")), style_table_cell)],
        [Paragraph("To Recipient", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("to")), style_table_cell)],
        [Paragraph("Cc Recipient", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("cc")), style_table_cell)],
        [Paragraph("Subject Line", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("subject")), style_table_cell)],
        [Paragraph("Date (IST)", style_table_cell_bold), Paragraph(format_ist_timestamp(data_dict.get("date")), style_table_cell)],
        [Paragraph("Reply-To Address", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("reply_to") or "Aligned with From"), style_table_cell)],
        [Paragraph("Return-Path Address", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("return_path") or "Unspecified"), style_table_cell)],
        [Paragraph("RFC 5322 Message-ID", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("message_id")), style_code)],
        [Paragraph("MIME Content-Type", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("content_type")), style_table_cell)],
        [Paragraph("Attachments", style_table_cell_bold), Paragraph(attach_desc, style_table_cell)],
    ]
    t_email_details = Table(email_details_data, colWidths=[2.0 * inch, 5.4 * inch])
    t_email_details.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), COLOR_PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
    ]))
    story.append(t_email_details)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 4. WHY IS THIS EMAIL SUSPICIOUS? (RISK FACTORS)
    # =========================================================================
    story.append(Paragraph("3. Suspicious Indicators &amp; Detected Risk Factors", style_h2))
    indicators = security_analysis.get("indicators") or []
    if indicators:
        risk_table_data = [
            [
                Paragraph("<b>Indicator Code / Title</b>", style_table_header),
                Paragraph("<b>Severity</b>", style_table_header),
                Paragraph("<b>Explanation</b>", style_table_header),
                Paragraph("<b>Evidence Source</b>", style_table_header),
            ]
        ]
        for ind in indicators:
            sev = (ind.get("severity") or "info").upper()
            evidence_list = ", ".join([sanitize_text(e) for e in ind.get("evidence", [])]) or "Security Analysis"
            risk_table_data.append([
                Paragraph(f"<b>{sanitize_text(ind.get('title'))}</b><br/><font color='#64748b'>{sanitize_text(ind.get('code'))}</font>", style_table_cell),
                Paragraph(f"<b>{sev}</b>", style_table_cell_bold),
                Paragraph(sanitize_text(ind.get("explanation")), style_table_cell),
                Paragraph(evidence_list, style_table_cell),
            ])
        t_risk = Table(risk_table_data, colWidths=[1.8 * inch, 0.9 * inch, 3.2 * inch, 1.5 * inch])
        t_risk.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_risk)
    else:
        story.append(Paragraph("No suspicious security indicators were detected by the threat engine.", style_body))
    
    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. EMAIL HEADER FORENSICS & RELAY ANALYSIS
    # =========================================================================
    story.append(Paragraph("4. Email Header Forensics &amp; Relay Chronology", style_h2))
    relay_hops = relay_analysis.get("relay_hops") or []
    probable_source = relay_analysis.get("probable_source_infrastructure") or {}
    probable_ip = probable_source.get("address") or "Unavailable"
    probable_reason = probable_source.get("reason") or "No probable source IP identified."

    story.append(Paragraph(f"<b>Probable Source Infrastructure IP:</b> <font color='#06b6d4'>{sanitize_text(probable_ip)}</font><br/>"
                           f"<b>Selection Rationale:</b> {sanitize_text(probable_reason)}", style_body))
    story.append(Spacer(1, 4))

    if relay_hops:
        hop_table_data = [
            [
                Paragraph("<b>Hop #</b>", style_table_header),
                Paragraph("<b>Hostnames</b>", style_table_header),
                Paragraph("<b>Extracted IPs &amp; Classification</b>", style_table_header),
            ]
        ]
        for hop in relay_hops:
            hop_num = hop.get("hop_number", 0)
            hostnames_str = ", ".join([sanitize_text(h) for h in hop.get("hostnames", [])]) or "Unspecified"
            ip_details = []
            for ip_obj in hop.get("extracted_ips", []):
                addr = sanitize_text(ip_obj.get("address"))
                classif = sanitize_text(ip_obj.get("classification"))
                cand = " [Source Candidate]" if ip_obj.get("is_public_source_candidate") else ""
                ip_details.append(f"{addr} ({classif}){cand}")
            ip_str = "<br/>".join(ip_details) if ip_details else "None extracted"

            hop_table_data.append([
                Paragraph(f"Hop #{hop_num}", style_table_cell_bold),
                Paragraph(hostnames_str, style_table_cell),
                Paragraph(ip_str, style_table_cell),
            ])

        t_hops = Table(hop_table_data, colWidths=[0.8 * inch, 3.3 * inch, 3.3 * inch])
        t_hops.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_hops)
    else:
        story.append(Paragraph("No Received relay hops available in email headers.", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 6. AUTHENTICATION ANALYSIS (SPF / DKIM / DMARC)
    # =========================================================================
    story.append(Paragraph("5. Authentication Analysis (RFC 8601)", style_h2))
    auth_results = security_analysis.get("authentication") or {}
    
    spf_res = auth_results.get("spf") or {}
    dkim_res = auth_results.get("dkim") or {}
    dmarc_res = auth_results.get("dmarc") or {}

    auth_table_data = [
        [
            Paragraph("<b>Protocol</b>", style_table_header),
            Paragraph("<b>Result</b>", style_table_header),
            Paragraph("<b>Evaluated Domain</b>", style_table_header),
            Paragraph("<b>Reason &amp; Properties</b>", style_table_header),
        ],
        [
            Paragraph("<b>SPF</b> (Sender Policy Framework)", style_table_cell),
            Paragraph(f"<b>{(spf_res.get('result') or 'NONE').upper()}</b>", style_table_cell_bold),
            Paragraph(sanitize_text(spf_res.get("domain") or auth_results.get("from_domain") or "None"), style_table_cell),
            Paragraph(sanitize_text(spf_res.get("reason") or "Evaluated from Authentication-Results header"), style_table_cell),
        ],
        [
            Paragraph("<b>DKIM</b> (DomainKeys Identified)", style_table_cell),
            Paragraph(f"<b>{(dkim_res.get('result') or 'NONE').upper()}</b>", style_table_cell_bold),
            Paragraph(sanitize_text(dkim_res.get("domain") or "None"), style_table_cell),
            Paragraph(sanitize_text(dkim_res.get("reason") or "Cryptographic signature evaluation"), style_table_cell),
        ],
        [
            Paragraph("<b>DMARC</b> (Domain-based Auth)", style_table_cell),
            Paragraph(f"<b>{(dmarc_res.get('result') or 'NONE').upper()}</b>", style_table_cell_bold),
            Paragraph(sanitize_text(dmarc_res.get("domain") or auth_results.get("from_domain") or "None"), style_table_cell),
            Paragraph(sanitize_text(dmarc_res.get("reason") or "Domain alignment &amp; policy check"), style_table_cell),
        ],
    ]
    t_auth = Table(auth_table_data, colWidths=[2.2 * inch, 1.0 * inch, 2.0 * inch, 2.2 * inch])
    t_auth.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
    ]))
    story.append(t_auth)
    
    alignment_notes = auth_results.get("alignment_notes") or []
    if alignment_notes:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Alignment &amp; Identity Notes:</b> " + "; ".join([sanitize_text(n) for n in alignment_notes]), style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 7. URL / DOMAIN INTELLIGENCE
    # =========================================================================
    story.append(Paragraph("6. URL &amp; Domain Intelligence", style_h2))
    url_analysis = security_analysis.get("urls") or {}
    urls_list = url_analysis.get("urls") or []
    domains_list = url_analysis.get("domains") or []

    if urls_list:
        url_table_data = [
            [
                Paragraph("<b>Extracted URL</b>", style_table_header),
                Paragraph("<b>Domain</b>", style_table_header),
                Paragraph("<b>Scheme</b>", style_table_header),
                Paragraph("<b>Associated Sender Domain</b>", style_table_header),
            ]
        ]
        for u in urls_list:
            url_table_data.append([
                Paragraph(sanitize_text(u.get("url")), style_code),
                Paragraph(sanitize_text(u.get("domain")), style_table_cell),
                Paragraph(sanitize_text(u.get("scheme", "")).upper(), style_table_cell),
                Paragraph(sanitize_text(u.get("associated_domain")), style_table_cell),
            ])
        t_urls = Table(url_table_data, colWidths=[3.2 * inch, 1.8 * inch, 0.8 * inch, 1.6 * inch])
        t_urls.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_urls)
    else:
        story.append(Paragraph("No embedded URLs extracted from email content.", style_body))

    # Threat Intelligence Observations for Domains / URLs
    provider_status = threat_intel.get("provider_status") or []
    degraded_providers = [p for p in provider_status if p.get("status") in ("degraded", "skipped", "error")]
    if degraded_providers:
        deg_msg = "Notice: Intelligence lookups were degraded/skipped for: " + ", ".join([f"<b>{p.get('provider')}</b> ({p.get('status')})" for p in degraded_providers]) + ". Lookups failed are explicitly recorded as unavailable and not assumed clean."
        story.append(Spacer(1, 4))
        story.append(Paragraph(deg_msg, style_alert_box))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 8. IP / INFRASTRUCTURE INTELLIGENCE
    # =========================================================================
    story.append(Paragraph("7. IP &amp; Infrastructure Intelligence", style_h2))
    observations = threat_intel.get("observations") or []
    ip_obs = [o for o in observations if o.get("entity_type") == "ip"]

    if ip_obs:
        ip_table_data = [
            [
                Paragraph("<b>IP Address</b>", style_table_header),
                Paragraph("<b>Provider</b>", style_table_header),
                Paragraph("<b>Reputation / Classification</b>", style_table_header),
                Paragraph("<b>Location / Details</b>", style_table_header),
            ]
        ]
        for o in ip_obs:
            ip_val = sanitize_text(o.get("entity"))
            prov = sanitize_text(o.get("provider"))
            data_field = o.get("data") or {}
            repu = sanitize_text(data_field.get("reputation") or o.get("kind") or "Observed")
            loc_parts = []
            if data_field.get("country"):
                loc_parts.append(f"Country: {data_field.get('country')}")
            if data_field.get("city"):
                loc_parts.append(f"City: {data_field.get('city')}")
            if data_field.get("asn"):
                loc_parts.append(f"ASN: {data_field.get('asn')}")
            loc_str = ", ".join(loc_parts) if loc_parts else "Geolocation unavailable — no verified public-IP coordinates."
            
            ip_table_data.append([
                Paragraph(ip_val, style_code),
                Paragraph(prov, style_table_cell),
                Paragraph(repu, style_table_cell),
                Paragraph(loc_str, style_table_cell),
            ])

        t_ip_intel = Table(ip_table_data, colWidths=[1.8 * inch, 1.5 * inch, 1.8 * inch, 2.3 * inch])
        t_ip_intel.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_ip_intel)
    else:
        story.append(Paragraph("Geolocation unavailable — no verified public-IP coordinates were available or eligible for infrastructure lookup.", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 9. GEOGRAPHIC INTELLIGENCE & CAVEAT
    # =========================================================================
    story.append(Paragraph("8. Geographic Intelligence", style_h2))
    verified_geo = False
    geo_details = "No verified public-IP coordinates were available in the telemetry."
    
    for o in observations:
        d = o.get("data") or {}
        if d.get("latitude") is not None and d.get("longitude") is not None:
            verified_geo = True
            geo_details = f"Verified Coordinates: Lat {d.get('latitude')}, Lon {d.get('longitude')} ({d.get('city', 'Unknown City')}, {d.get('country', 'Unknown Country')})"
            break

    story.append(Paragraph(f"<b>Geolocation Telemetry:</b> {sanitize_text(geo_details)}", style_body))
    story.append(Spacer(1, 3))
    # Mandatory Caveat Language
    caveat_text = "<b>Attribution Boundary Caveat:</b> Geolocation represents probable source infrastructure and does not establish the attacker's physical location."
    story.append(Paragraph(caveat_text, style_alert_box))
    story.append(Spacer(1, 10))

    # =========================================================================
    # 10. CORRELATION / ATTACK GRAPH
    # =========================================================================
    story.append(Paragraph("9. Correlation &amp; Threat Relationships", style_h2))
    correlations = data_dict.get("correlations") or []
    if correlations:
        corr_table_data = [
            [
                Paragraph("<b>Correlation Code</b>", style_table_header),
                Paragraph("<b>Relationship</b>", style_table_header),
                Paragraph("<b>Entities &amp; Explanation</b>", style_table_header),
                Paragraph("<b>Confidence</b>", style_table_header),
            ]
        ]
        for c in correlations:
            entities_str = ", ".join([sanitize_text(e) for e in c.get("entities", [])])
            explanation = f"{sanitize_text(c.get('explanation'))}<br/><font color='#64748b'>Entities: {entities_str}</font>"
            corr_table_data.append([
                Paragraph(f"<b>{sanitize_text(c.get('code'))}</b>", style_table_cell),
                Paragraph(sanitize_text(c.get("relationship")), style_table_cell_bold),
                Paragraph(explanation, style_table_cell),
                Paragraph((c.get("confidence") or "medium").upper(), style_table_cell),
            ])
        t_corr = Table(corr_table_data, colWidths=[1.5 * inch, 1.8 * inch, 3.2 * inch, 0.9 * inch])
        t_corr.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_corr)
    else:
        story.append(Paragraph("No cross-entity correlations generated for this investigation.", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 11. AI FORENSIC INVESTIGATION
    # =========================================================================
    story.append(Paragraph("10. Autonomous AI Investigation Record", style_h2))
    if ai_investigation:
        exec_source = sanitize_text((ai_investigation.get("source") or "AI_AGENT").upper())
        provider = sanitize_text(ai_investigation.get("provider") or "AI AGENT")
        model_name = sanitize_text(ai_investigation.get("model") or "N/A")
        iterations = ai_investigation.get("iterations", 1)
        reasoning = sanitize_text(ai_investigation.get("reasoning") or ai_investigation.get("summary") or "Autonomous forensic evaluation completed.")

        ai_meta_data = [
            [
                Paragraph(f"<b>EXECUTION SOURCE:</b> {exec_source}", style_table_cell),
                Paragraph(f"<b>PROVIDER:</b> {provider}", style_table_cell),
                Paragraph(f"<b>MODEL:</b> {model_name}", style_table_cell),
                Paragraph(f"<b>ITERATIONS:</b> {iterations}", style_table_cell),
            ]
        ]
        t_ai_meta = Table(ai_meta_data, colWidths=[1.85 * inch] * 4)
        t_ai_meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_ai_meta)
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Structured AI Findings &amp; Rationale:</b><br/>{reasoning}", style_body))
    else:
        story.append(Paragraph("AI analysis unavailable or failed. No autonomous AI investigation record was generated.", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 12. RECOMMENDED ACTIONS
    # =========================================================================
    story.append(Paragraph("11. Recommended Actions", style_h2))
    if recommended_actions:
        rec_table_data = [
            [
                Paragraph("<b>Priority</b>", style_table_header),
                Paragraph("<b>Action &amp; Rationale</b>", style_table_header),
                Paragraph("<b>Supporting Evidence</b>", style_table_header),
            ]
        ]
        for act in recommended_actions:
            prio = (act.get("priority") or "routine").upper()
            title = sanitize_text(act.get("action") or act.get("title") or "Recommended Action")
            rat = sanitize_text(act.get("rationale") or act.get("reason") or "")
            ev_str = ", ".join([sanitize_text(e) for e in act.get("evidence", [])]) or "Security Analysis"
            
            act_text = f"<b>{title}</b>"
            if rat:
                act_text += f"<br/><font color='#64748b'>{rat}</font>"

            rec_table_data.append([
                Paragraph(f"<b>{prio}</b>", style_table_cell_bold),
                Paragraph(act_text, style_table_cell),
                Paragraph(ev_str, style_table_cell),
            ])
        t_rec = Table(rec_table_data, colWidths=[1.2 * inch, 4.4 * inch, 1.8 * inch])
        t_rec.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
        ]))
        story.append(t_rec)
    else:
        story.append(Paragraph("No mitigation actions recommended.", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 13. CONFIDENCE & ATTRIBUTION
    # =========================================================================
    story.append(Paragraph("12. Confidence &amp; Attribution Assessment", style_h2))
    conf_level = (confidence.get("level") or risk_assessment.get("confidence", {}).get("level") or "medium").upper()
    conf_exp = sanitize_text(confidence.get("explanation") or risk_assessment.get("confidence", {}).get("explanation") or "Assessment based on available header & content telemetry.")
    attr_status = sanitize_text(attribution.get("status") or "infrastructure_only")
    attr_assess = sanitize_text(attribution.get("assessment") or "The evidence supports identification of suspicious infrastructure, but does not establish the attacker's physical identity.")

    story.append(Paragraph(f"<b>Confidence Assessment Level:</b> {conf_level}<br/>"
                           f"<b>Confidence Rationale:</b> {conf_exp}<br/><br/>"
                           f"<b>Attribution Status:</b> <font color='#06b6d4'>{attr_status}</font><br/>"
                           f"<b>Attribution Statement:</b> <i>\"{attr_assess}\"</i>", style_body))

    attr_limits = attribution.get("limitations") or data_dict.get("attribution_limitations") or []
    if attr_limits:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Attribution Constraints &amp; Limitations:</b>", style_body_bold))
        for lim in attr_limits:
            story.append(Paragraph(f"• {sanitize_text(lim)}", style_body))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 14. EVIDENCE / CHAIN OF CUSTODY
    # =========================================================================
    story.append(Paragraph("13. Evidence &amp; Chain of Custody", style_h2))
    custody_data = [
        [Paragraph("<b>Evidence Artifact Property</b>", style_table_header), Paragraph("<b>Recorded Value</b>", style_table_header)],
        [Paragraph("Evidence SHA-256 Digest", style_table_cell_bold), Paragraph(evidence_sha256, style_code)],
        [Paragraph("Analysis Timestamp (IST)", style_table_cell_bold), Paragraph(report_gen_time, style_table_cell)],
        [Paragraph("Original Message-ID", style_table_cell_bold), Paragraph(sanitize_text(data_dict.get("message_id") or "Unrecorded"), style_code)],
        [Paragraph("Ingestion Protocol", style_table_cell_bold), Paragraph("RFC 5322 MIME Parser", style_table_cell)],
    ]
    t_custody = Table(custody_data, colWidths=[2.2 * inch, 5.2 * inch])
    t_custody.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), COLOR_PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_LIGHT]),
    ]))
    story.append(t_custody)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 15. FORENSIC LIMITATIONS
    # =========================================================================
    story.append(Paragraph("14. Forensic Limitations &amp; Scope Boundary", style_h2))
    limitations_list = confidence.get("limitations") or investigation_summary.get("limitations") or []
    if not limitations_list:
        limitations_list = [
            "Analysis is restricted to static header, body content, and external threat intelligence lookups.",
            "Private or reserved RFC 1918/5737 IP addresses cannot be geolocated.",
            "No dynamic payload execution or URL detonation was performed.",
        ]
    
    for lim in limitations_list:
        story.append(Paragraph(f"• {sanitize_text(lim)}", style_body))

    # Build Document
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
