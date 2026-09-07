import ipaddress
import re
from email.utils import getaddresses

from app.schemas.email import EmailAnalysisResponse
from app.schemas.security import (
    AuthenticationResultsAnalysis,
    ContentSignals,
    SecurityIndicator,
    URLDomainAnalysis,
)


def _domains(addresses: str | None) -> set[str]:
    if not addresses:
        return set()
    return {
        address.rsplit("@", 1)[1].lower()
        for _, address in getaddresses([addresses])
        if "@" in address
    }


def _authentication_indicators(
    auth: AuthenticationResultsAnalysis,
) -> list[SecurityIndicator]:
    indicators: list[SecurityIndicator] = []
    for item in (auth.spf, auth.dkim, auth.dmarc):
        if item is None or item.result in {"pass", "none", "neutral"}:
            continue
        severity = "high" if item.result in {"fail", "permerror"} else "medium"
        indicators.append(
            SecurityIndicator(
                code=f"{item.method}_{item.result}",
                category="authentication",
                severity=severity,
                title=f"{item.method.upper()} authentication {item.result}",
                explanation=(
                    f"The Authentication-Results header reports {item.method.upper()}={item.result}. "
                    "This is a signal from the receiving mail system, not a new DNS or cryptographic check."
                ),
                evidence=[item.raw],
            )
        )
    return indicators


def build_security_indicators(
    email: EmailAnalysisResponse,
    auth: AuthenticationResultsAnalysis,
    url_analysis: URLDomainAnalysis,
    content: ContentSignals,
) -> list[SecurityIndicator]:
    """Create deterministic, evidence-backed indicators from local email data."""
    indicators = _authentication_indicators(auth)
    for signal in content.signals:
        indicators.append(
            SecurityIndicator(
                code=f"content_{signal.code}",
                category="content",
                severity=signal.severity,
                title=signal.code.replace("_", " ").title(),
                explanation=signal.explanation,
                evidence=signal.evidence,
            )
        )

    for link in url_analysis.urls:
        try:
            host_is_ip = ipaddress.ip_address(link.domain).version in (4, 6)
        except ValueError:
            host_is_ip = False
        if host_is_ip:
            indicators.append(
                SecurityIndicator(
                    code="url_ip_literal",
                    category="url",
                    severity="high",
                    title="Link uses an IP address",
                    explanation="The link points directly to an IP address instead of a named domain.",
                    evidence=[link.url],
                )
            )
        if "xn--" in link.domain:
            indicators.append(
                SecurityIndicator(
                    code="url_punycode",
                    category="url",
                    severity="medium",
                    title="Link uses an internationalized/punycode domain",
                    explanation="Punycode can make a look-alike domain harder to recognize.",
                    evidence=[link.domain],
                )
            )

    sender_domains = _domains(email.from_)
    reply_domains = _domains(email.reply_to)
    if sender_domains and reply_domains and sender_domains.isdisjoint(reply_domains):
        indicators.append(
            SecurityIndicator(
                code="reply_to_mismatch",
                category="identity",
                severity="medium",
                title="Reply-To domain differs from sender",
                explanation="Replies would be sent to a different domain than the visible sender.",
                evidence=[
                    f"From: {', '.join(sorted(sender_domains))}",
                    f"Reply-To: {', '.join(sorted(reply_domains))}",
                ],
            )
        )
    if auth.dkim and auth.dkim.domain and sender_domains:
        dkim_domain = auth.dkim.domain.lower().rstrip(".")
        if all(
            dkim_domain != sender_domain
            and not dkim_domain.endswith(f".{sender_domain}")
            for sender_domain in sender_domains
        ):
            indicators.append(
                SecurityIndicator(
                    code="dkim_alignment_mismatch",
                    category="identity",
                    severity="low",
                    title="DKIM signing domain differs from sender",
                    explanation="The reported DKIM signing domain does not align with the visible From domain.",
                    evidence=[f"From: {', '.join(sorted(sender_domains))}", f"DKIM: {dkim_domain}"],
                )
            )
    for item in url_analysis.urls:
        if sender_domains and all(
            not _same_or_subdomain(item.domain, sender_domain)
            for sender_domain in sender_domains
        ):
            indicators.append(
                SecurityIndicator(
                    code="url_sender_domain_mismatch",
                    category="identity",
                    severity="medium",
                    title="URL hostname differs from sender domain",
                    explanation=(
                        "The message links to a hostname that is not the sender's "
                        "domain or a subdomain of it."
                    ),
                    evidence=[f"URL host: {item.domain}", f"Sender: {', '.join(sorted(sender_domains))}"],
                )
            )
        if item.scheme != "https":
            indicators.append(
                SecurityIndicator(
                    code="url_not_https",
                    category="url",
                    severity="low",
                    title="Link does not use HTTPS",
                    explanation="The extracted URL uses a non-HTTPS scheme; transport protection cannot be assumed.",
                    evidence=[item.url],
                )
            )
    if len(url_analysis.urls) > 5:
        indicators.append(
            SecurityIndicator(
                code="excessive_urls",
                category="url",
                severity="low",
                title="Message contains many URLs",
                explanation="The message contains more than five distinct URLs, which merits review in context.",
                evidence=[str(len(url_analysis.urls))],
            )
        )
    if email.return_path and email.from_:
        return_domains = _domains(email.return_path)
        if sender_domains and return_domains and sender_domains.isdisjoint(return_domains):
            indicators.append(
                SecurityIndicator(
                    code="return_path_mismatch",
                    category="identity",
                    severity="low",
                    title="Return-Path domain differs from sender",
                    explanation="The envelope return domain differs from the visible sender domain; this can be legitimate but is worth review.",
                    evidence=[
                        f"From: {', '.join(sorted(sender_domains))}",
                        f"Return-Path: {', '.join(sorted(return_domains))}",
                    ],
                )
            )
    for attachment in email.attachments:
        if attachment.content_type in {"application/x-msdownload", "application/x-executable"} or (
            attachment.filename
            and attachment.filename.lower().endswith((".exe", ".js", ".vbs", ".scr", ".bat", ".cmd"))
        ):
            indicators.append(
                SecurityIndicator(
                    code="suspicious_attachment_type",
                    category="attachment",
                    severity="high",
                    title="Attachment type requires caution",
                    explanation="The attachment uses an executable or script-like type; it was not opened or executed.",
                    evidence=[attachment.filename or attachment.content_type],
                )
            )
    combined_text = " ".join(
        value for value in (email.subject, email.body_text, email.body_html) if value
    )
    suspension_match = re.search(
        r"\b(?:account|profile|access)\b.{0,40}\b(?:suspend(?:ed|ing|ion)?|deactivat(?:ed|ion|e)?|"
        r"disabled|closed|terminat(?:ed|ion))\b|\b(?:suspend(?:ed|ing|ion)?|deactivat(?:ed|ion|e)?|"
        r"disabled|closed|terminat(?:ed|ion))\b.{0,40}\b(?:account|profile|access)\b",
        re.sub(r"<[^>]+>", " ", combined_text),
        re.IGNORECASE | re.DOTALL,
    )
    if suspension_match:
        indicators.append(
            SecurityIndicator(
                code="account_suspension_or_deactivation",
                category="content",
                severity="high",
                title="Account suspension or deactivation threat",
                explanation=(
                    "The message threatens account suspension, deactivation, or closure, "
                    "a common pressure tactic in credential phishing."
                ),
                evidence=[suspension_match.group(0).strip()],
            )
        )
    return indicators


def _same_or_subdomain(left: str, right: str) -> bool:
    left = left.lower().rstrip(".")
    right = right.lower().rstrip(".")
    return left == right or left.endswith(f".{right}")
