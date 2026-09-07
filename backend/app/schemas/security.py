from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field


AuthStatus = Literal[
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "skipped",
    "unknown",
]
IndicatorSeverity = Literal["info", "low", "medium", "high", "critical"]


class AuthenticationMethodResult(BaseModel):
    method: str
    result: AuthStatus
    domain: str | None = None
    selector: str | None = None
    identity: str | None = None
    reason: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)
    raw: str


class AuthenticationResultsAnalysis(BaseModel):
    headers: list[str] = Field(default_factory=list)
    authserv_ids: list[str] = Field(default_factory=list)
    results: list[AuthenticationMethodResult] = Field(default_factory=list)
    spf: AuthenticationMethodResult | None = None
    dkim: AuthenticationMethodResult | None = None
    dmarc: AuthenticationMethodResult | None = None
    from_domain: str | None = None
    return_path_domain: str | None = None
    reply_to_domain: str | None = None
    alignment_notes: list[str] = Field(default_factory=list)


class ExtractedURL(BaseModel):
    url: str
    normalized_url: str
    domain: str
    scheme: str
    port: int | None = None
    path: str = ""
    has_query: bool = False
    is_https: bool = False
    associated_domain: str
    source: Literal["body_text", "body_html", "header"] = "body_text"


class ExtractedDomain(BaseModel):
    domain: str
    source: Literal[
        "from", "reply_to", "return_path", "received", "url", "dkim", "dmarc",
        "body_text", "body_html", "header",
    ] = "body_text"


class URLDomainAnalysis(BaseModel):
    urls: list[ExtractedURL] = Field(default_factory=list)
    domains: list[ExtractedDomain] = Field(default_factory=list)


class ContentSignal(BaseModel):
    code: str
    category: Literal["phishing", "bec", "social_engineering"]
    severity: IndicatorSeverity
    explanation: str
    evidence: list[str] = Field(default_factory=list)


class ContentSignals(BaseModel):
    signals: list[ContentSignal] = Field(default_factory=list)
    normalized_text_length: int = 0


class SecurityIndicator(BaseModel):
    code: str
    category: Literal["authentication", "url", "content", "identity", "attachment"]
    severity: IndicatorSeverity
    title: str
    explanation: str
    evidence: list[str] = Field(default_factory=list)


class SecurityAnalysis(BaseModel):
    summary: str
    indicators: list[SecurityIndicator] = Field(default_factory=list)
    authentication_results: AuthenticationResultsAnalysis = Field(alias="authentication")
    url_analysis: URLDomainAnalysis = Field(alias="urls")
    domains: list[ExtractedDomain] = Field(default_factory=list)
    content_signals: ContentSignals

    model_config = {"populate_by_name": True}
