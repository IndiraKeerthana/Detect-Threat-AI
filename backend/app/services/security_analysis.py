from app.schemas.email import EmailAnalysisResponse
from app.schemas.security import SecurityAnalysis
from app.services.authentication_results import parse_authentication_results
from app.services.content_signals import analyze_content_signals
from app.services.security_indicators import build_security_indicators
from app.services.url_extractor import extract_urls_and_domains
from app.services.url_extractor import extract_domains


def analyze_security(email: EmailAnalysisResponse) -> SecurityAnalysis:
    auth = parse_authentication_results(email.authentication_results)
    from_domain = _address_domain(email.from_)
    return_path_domain = _address_domain(email.return_path)
    reply_to_domain = _address_domain(email.reply_to)
    auth.from_domain = from_domain
    auth.return_path_domain = return_path_domain
    auth.reply_to_domain = reply_to_domain
    if auth.dkim and from_domain and auth.dkim.domain:
        auth.alignment_notes.append(
            "DKIM signing domain aligns with From domain."
            if _same_or_subdomain(auth.dkim.domain, from_domain)
            else "DKIM signing domain does not align with From domain."
        )
    if auth.dmarc and from_domain and auth.dmarc.domain:
        auth.alignment_notes.append(
            "DMARC header.from domain was reported by Authentication-Results."
        )
    url_analysis = extract_urls_and_domains(
        body_text=email.body_text,
        body_html=email.body_html,
        headers=(*email.received, email.from_, email.reply_to, email.return_path),
    )
    domains = extract_domains(
        [
            ("from", email.from_ or ""),
            ("reply_to", email.reply_to or ""),
            ("return_path", email.return_path or ""),
            ("received", "\n".join(email.received)),
            ("url", "\n".join(item.domain for item in url_analysis.urls)),
            ("dkim", auth.dkim.domain if auth.dkim and auth.dkim.domain else ""),
            ("dmarc", auth.dmarc.domain if auth.dmarc and auth.dmarc.domain else ""),
        ]
    )
    content = analyze_content_signals(email.subject, email.body_text, email.body_html)
    indicators = build_security_indicators(email, auth, url_analysis, content)

    summary = (
        "No strong local phishing or BEC indicators were detected."
        if not indicators
        else f"Detected {len(indicators)} explainable security indicator(s); review the evidence before trusting this message."
    )
    return SecurityAnalysis(
        summary=summary,
        indicators=indicators,
        authentication_results=auth,
        url_analysis=url_analysis,
        domains=domains,
        content_signals=content,
    )


def _address_domain(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    return value.rsplit("@", 1)[-1].strip(" >").lower().rstrip(".")


def _same_or_subdomain(left: str, right: str) -> bool:
    left = left.lower().rstrip(".")
    right = right.lower().rstrip(".")
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")
