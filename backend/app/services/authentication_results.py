import re
from collections.abc import Iterable

from app.schemas.security import (
    AuthenticationMethodResult,
    AuthenticationResultsAnalysis,
    AuthStatus,
)

_METHOD_RE = re.compile(r"^(?P<method>[a-z][a-z0-9_-]*)=(?P<result>[a-z]+)(?P<rest>.*)$", re.I)
_PROPERTY_RE = re.compile(
    r"(?P<name>[a-z][a-z0-9_.-]*)=(?P<value>[^\s;]+)", re.I
)
_VALID_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "skipped",
}


def _status(value: str) -> AuthStatus:
    return value.lower() if value.lower() in _VALID_RESULTS else "unknown"


def _method_result(method: str, result: str, text: str) -> AuthenticationMethodResult:
    properties = {
        match.group("name").lower(): match.group("value")
        for match in _PROPERTY_RE.finditer(text)
    }
    identity = properties.get("smtp.mailfrom") or properties.get("header.from")
    domain = properties.get("header.d") or properties.get("header.from")
    if method.lower() == "spf":
        domain = properties.get("smtp.mailfrom") or properties.get("header.from")
    return AuthenticationMethodResult(
        method=method.lower(),
        result=_status(result),
        domain=domain,
        selector=properties.get("header.s"),
        identity=identity,
        reason=properties.get("reason"),
        properties=properties,
        raw=text.strip(),
    )


def parse_authentication_results(headers: Iterable[str]) -> AuthenticationResultsAnalysis:
    """Parse Authentication-Results fields without attempting DNS or cryptographic checks."""
    header_values = []
    for value in headers:
        header = str(value).strip()
        if not header:
            continue
        header_values.append(
            re.sub(r"(?i)^authentication-results\s*:\s*", "", header)
        )
    analysis = AuthenticationResultsAnalysis(headers=header_values)
    for header in header_values:
        chunks = [chunk.strip() for chunk in header.split(";") if chunk.strip()]
        if not chunks:
            continue
        authserv_id = chunks[0].split(None, 1)[0]
        if "=" not in authserv_id:
            analysis.authserv_ids.append(authserv_id)
        for chunk in chunks[1:] if "=" not in chunks[0] else chunks:
            match = _METHOD_RE.match(chunk)
            if not match:
                continue
            item = _method_result(
                match.group("method"), match.group("result"), chunk
            )
            analysis.results.append(item)
            if item.method == "spf" and analysis.spf is None:
                analysis.spf = item
            elif item.method == "dkim" and analysis.dkim is None:
                analysis.dkim = item
            elif item.method == "dmarc" and analysis.dmarc is None:
                analysis.dmarc = item
    return analysis


# A descriptive alias useful to callers that prefer "analyze" terminology.
analyze_authentication_results = parse_authentication_results
