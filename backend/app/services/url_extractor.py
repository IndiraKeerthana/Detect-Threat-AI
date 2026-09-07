import html
import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

from app.schemas.security import ExtractedDomain, ExtractedURL, URLDomainAnalysis

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>'\"]+")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)
_TRAILING = ".,;:!?)]}>\"'"


def _clean_url(value: str) -> str:
    return html.unescape(value).rstrip(_TRAILING)


def _domain(value: str) -> str | None:
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def extract_domains(values: Iterable[tuple[str, str]]) -> list[ExtractedDomain]:
    domains: list[ExtractedDomain] = []
    seen: set[str] = set()
    for source, value in values:
        if not value:
            continue
        for raw_domain in _DOMAIN_RE.findall(html.unescape(value)):
            domain = raw_domain.lower().rstrip(".")
            if domain not in seen:
                domains.append(ExtractedDomain(domain=domain, source=source))
                seen.add(domain)
    return domains


def extract_urls_and_domains(
    text: str | None = None,
    *,
    body_text: str | None = None,
    body_html: str | None = None,
    headers: Iterable[str] | None = None,
) -> URLDomainAnalysis:
    """Extract links and domains locally; no network or reputation lookup is performed."""
    sources = [
        ("body_text", body_text if body_text is not None else text),
        ("body_html", body_html),
        ("header", " ".join(value for value in (headers or []) if value)),
    ]
    urls: list[ExtractedURL] = []
    domains: list[ExtractedDomain] = []
    seen_urls: set[str] = set()
    seen_domains: set[str] = set()

    def add_domain(domain: str, source: str) -> None:
        key = domain.lower().rstrip(".")
        if key and key not in seen_domains:
            domains.append(ExtractedDomain(domain=key, source=source))
            seen_domains.add(key)

    for source, value in sources:
        if not value:
            continue
        content = html.unescape(value)
        for raw_url in _URL_RE.findall(content):
            url = _clean_url(raw_url)
            domain = _domain(url)
            if not domain:
                continue
            key = url.lower()
            if key not in seen_urls:
                parsed = urlsplit(url)
                scheme = parsed.scheme.lower()
                normalized = urlunsplit(
                    (scheme, parsed.netloc.lower(), parsed.path or "", parsed.query, "")
                )
                urls.append(
                    ExtractedURL(
                        url=url,
                        normalized_url=normalized,
                        domain=domain,
                        scheme=scheme,
                        port=parsed.port,
                        path=parsed.path or "",
                        has_query=bool(parsed.query),
                        is_https=scheme == "https",
                        associated_domain=domain,
                        source=source if source in {"body_text", "body_html", "header"} else "header",
                    )
                )
                seen_urls.add(key)
            add_domain(domain, source)
        for raw_domain in _DOMAIN_RE.findall(content):
            add_domain(raw_domain, source)
    return URLDomainAnalysis(urls=urls, domains=domains)


extract_urls = extract_urls_and_domains
