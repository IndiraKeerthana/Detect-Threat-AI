import re

from app.schemas.security import ContentSignal, ContentSignals

_RULES: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    (
        "urgent_action",
        "social_engineering",
        "high",
        "The message uses urgency or a deadline to pressure the recipient into acting quickly.",
        (r"\burgent\b", r"\bimmediately\b", r"\basap\b", r"\bwithin\s+\d+\s*(?:hour|minute)s?\b", r"\bdeadline\b"),
    ),
    (
        "credential_request",
        "phishing",
        "high",
        "The message asks for a password, login, verification code, or account sign-in.",
        (r"\b(?:password|passcode|verification code|one[- ]time code|otp)\b", r"\b(?:sign|log)\s*in\b", r"\bverify\s+(?:your\s+)?account\b"),
    ),
    (
        "payment_request",
        "bec",
        "high",
        "The message requests a transfer, invoice payment, gift card, or change to payment details.",
        (r"\bwire\s+transfer\b", r"\bgift\s+cards?\b", r"\bpay(?:ment)?\b", r"\binvoice\b", r"\bbank\s+details?\b", r"\baccount\s+number\b"),
    ),
    (
        "secrecy_or_impersonation",
        "bec",
        "medium",
        "The message asks for secrecy or frames the request as coming from an executive or manager.",
        (r"\bkeep\s+this\s+(?:confidential|secret)\b", r"\bdon'?t\s+tell\b", r"\b(?:ceo|cfo|director|executive)\b"),
    ),
    (
        "callback_or_contact_change",
        "bec",
        "medium",
        "The message asks the recipient to use a new phone number, address, or reply channel.",
        (r"\bnew\s+(?:bank|wire|payment)\s+details?\b", r"\bcall\s+me\s+on\b", r"\buse\s+this\s+(?:number|email)\b"),
    ),
)


def analyze_content_signals(
    subject: str | None = None,
    body_text: str | None = None,
    body_html: str | None = None,
) -> ContentSignals:
    combined = "\n".join(part for part in (subject, body_text, body_html) if part)
    normalized = re.sub(r"<[^>]+>", " ", combined)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    lowered = normalized.lower()
    signals: list[ContentSignal] = []
    for code, category, severity, explanation, patterns in _RULES:
        evidence: list[str] = []
        for pattern in patterns:
            match = re.search(pattern, lowered)
            if match:
                evidence.append(match.group(0))
        if evidence:
            signals.append(
                ContentSignal(
                    code=code,
                    category=category,
                    severity=severity,
                    explanation=explanation,
                    evidence=sorted(set(evidence)),
                )
            )
    return ContentSignals(signals=signals, normalized_text_length=len(normalized))
