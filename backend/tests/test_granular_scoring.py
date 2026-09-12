import unittest
from app.schemas.email import EmailAnalysisResponse, AttachmentMetadata
from app.schemas.security import (
    AuthenticationResultsAnalysis,
    AuthenticationMethodResult,
    ContentSignals,
    ContentSignal,
    URLDomainAnalysis,
    ExtractedURL,
    SecurityAnalysis,
)
from app.schemas.threat_intelligence import ThreatIntelligence, ThreatObservation
from app.schemas.investigation import EvidenceGraph
from app.services.security_indicators import build_security_indicators
from app.services.threat_engine import assess_threat


def _make_email(
    *,
    subject: str = "Subject",
    body: str = "Body text",
    from_addr: str = "sender@domain.com",
    to_addr: str = "recipient@domain.com",
    reply_to: str | None = None,
    attachments: list[AttachmentMetadata] | None = None,
) -> EmailAnalysisResponse:
    return EmailAnalysisResponse(
        from_=from_addr,
        to=to_addr,
        cc=None,
        bcc=None,
        subject=subject,
        date="Sat, 12 Sep 2026 12:00:00 +0000",
        message_id="<test@domain.com>",
        reply_to=reply_to,
        return_path=None,
        mime_version="1.0",
        content_type="text/plain",
        received=[],
        body_text=body,
        body_html=None,
        attachments=attachments or [],
    )


class GranularScoringTest(unittest.TestCase):
    def test_1_legitimate_email(self):
        email = _make_email(subject="Team Sync", body="Hi team, see you at 2pm.")
        auth = AuthenticationResultsAnalysis(
            spf=AuthenticationMethodResult(method="spf", result="pass", raw="spf=pass"),
            dkim=AuthenticationMethodResult(method="dkim", result="pass", raw="dkim=pass"),
            dmarc=AuthenticationMethodResult(method="dmarc", result="pass", raw="dmarc=pass"),
        )
        sec = SecurityAnalysis(
            summary="Clean",
            authentication=auth,
            urls=URLDomainAnalysis(),
            content_signals=ContentSignals(),
            indicators=build_security_indicators(email, auth, URLDomainAnalysis(), ContentSignals())
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.level, "benign")

    def test_2_mildly_suspicious_email(self):
        email = _make_email(subject="Newsletter", body="Link: http://marketing.com/page", reply_to="alt@external.com")
        auth = AuthenticationResultsAnalysis(spf=AuthenticationMethodResult(method="spf", result="pass", raw="spf=pass"))
        urls = URLDomainAnalysis(urls=[ExtractedURL(url="http://marketing.com/page", normalized_url="http://marketing.com/page", domain="marketing.com", scheme="http", associated_domain="marketing.com")])
        sec = SecurityAnalysis(
            summary="Mild",
            authentication=auth,
            urls=urls,
            content_signals=ContentSignals(),
            indicators=build_security_indicators(email, auth, urls, ContentSignals())
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertGreater(assessment.score, 0)
        self.assertLess(assessment.score, 40)

    def test_3_phishing(self):
        email = _make_email(subject="Update Required", body="Verify account credentials at http://verify-domain.net")
        auth = AuthenticationResultsAnalysis(dmarc=AuthenticationMethodResult(method="dmarc", result="fail", raw="dmarc=fail"))
        urls = URLDomainAnalysis(urls=[ExtractedURL(url="http://verify-domain.net", normalized_url="http://verify-domain.net", domain="verify-domain.net", scheme="http", associated_domain="verify-domain.net")])
        content = ContentSignals(signals=[ContentSignal(code="credential_request", category="phishing", severity="high", title="Credential Request", explanation="Requests credentials")])
        sec = SecurityAnalysis(
            summary="Phishing",
            authentication=auth,
            urls=urls,
            content_signals=content,
            indicators=build_security_indicators(email, auth, urls, content)
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertGreaterEqual(assessment.score, 40)
        self.assertIn(assessment.classification, ["phishing", "suspicious"])

    def test_4_credential_phishing(self):
        email = _make_email(subject="URGENT: Password Expired", body="Click http://192.168.1.1/login to verify password immediately or access will be suspended.")
        auth = AuthenticationResultsAnalysis(
            spf=AuthenticationMethodResult(method="spf", result="fail", raw="spf=fail"),
            dmarc=AuthenticationMethodResult(method="dmarc", result="fail", raw="dmarc=fail")
        )
        urls = URLDomainAnalysis(urls=[ExtractedURL(url="http://192.168.1.1/login", normalized_url="http://192.168.1.1/login", domain="192.168.1.1", scheme="http", associated_domain="192.168.1.1")])
        content = ContentSignals(signals=[
            ContentSignal(code="credential_request", category="phishing", severity="high", title="Credential Request", explanation="Requests credentials", evidence=["verify password"]),
            ContentSignal(code="urgency", category="phishing", severity="medium", title="Urgency", explanation="Urgent tone", evidence=["URGENT"])
        ])
        sec = SecurityAnalysis(
            summary="Credential Phish",
            authentication=auth,
            urls=urls,
            content_signals=content,
            indicators=build_security_indicators(email, auth, urls, content)
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertGreaterEqual(assessment.score, 70)
        self.assertEqual(assessment.level, "critical")

    def test_5_bec(self):
        email = _make_email(subject="Confidential Wire Transfer", body="Please wire $45,000 to vendor account immediately.", reply_to="ceo-personal@gmail.com")
        auth = AuthenticationResultsAnalysis(spf=AuthenticationMethodResult(method="spf", result="softfail", raw="spf=softfail"))
        content = ContentSignals(signals=[
            ContentSignal(code="payment_request", category="bec", severity="high", title="Payment Request", explanation="Wire transfer", evidence=["wire"]),
            ContentSignal(code="secrecy_or_impersonation", category="bec", severity="high", title="Secrecy", explanation="Confidential", evidence=["confidential"])
        ])
        sec = SecurityAnalysis(
            summary="BEC",
            authentication=auth,
            urls=URLDomainAnalysis(),
            content_signals=content,
            indicators=build_security_indicators(email, auth, URLDomainAnalysis(), content)
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertGreaterEqual(assessment.score, 45)
        self.assertEqual(assessment.classification, "bec")

    def test_6_mixed_evidence(self):
        email = _make_email(subject="Invoice #1024", body="Remit payment to new account.")
        auth = AuthenticationResultsAnalysis(
            spf=AuthenticationMethodResult(method="spf", result="pass", raw="spf=pass"),
            dkim=AuthenticationMethodResult(method="dkim", result="pass", raw="dkim=pass")
        )
        content = ContentSignals(signals=[ContentSignal(code="payment_request", category="bec", severity="high", title="Payment Request", explanation="Payment", evidence=["payment"])])
        sec = SecurityAnalysis(
            summary="Mixed",
            authentication=auth,
            urls=URLDomainAnalysis(),
            content_signals=content,
            indicators=build_security_indicators(email, auth, URLDomainAnalysis(), content)
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertLess(assessment.score, 30)

    def test_7_insufficient_evidence(self):
        email = _make_email(subject="Hello", body="Just checking in")
        sec = SecurityAnalysis(
            summary="Minimal",
            authentication=AuthenticationResultsAnalysis(),
            urls=URLDomainAnalysis(),
            content_signals=ContentSignals(),
            indicators=[]
        )
        assessment, _, _ = assess_threat(sec, ThreatIntelligence(), EvidenceGraph())
        self.assertEqual(assessment.score, 0)

    def test_8_multiple_correlated_indicators_without_double_counting(self):
        email = _make_email(subject="Alert", body="Link http://1.2.3.4/pay")
        auth = AuthenticationResultsAnalysis(spf=AuthenticationMethodResult(method="spf", result="fail", raw="spf=fail"))
        urls = URLDomainAnalysis(urls=[ExtractedURL(url="http://1.2.3.4/pay", normalized_url="http://1.2.3.4/pay", domain="1.2.3.4", scheme="http", associated_domain="1.2.3.4")])
        intel = ThreatIntelligence(observations=[
            ThreatObservation(provider="AbuseIPDB", entity_type="ip", entity="1.2.3.4", kind="reputation", data={"abuseConfidenceScore": 90}),
            ThreatObservation(provider="VirusTotal", entity_type="ip", entity="1.2.3.4", kind="reputation", data={"last_analysis_stats": {"malicious": 10}}),
        ])
        sec = SecurityAnalysis(
            summary="Correlated",
            authentication=auth,
            urls=urls,
            content_signals=ContentSignals(),
            indicators=build_security_indicators(email, auth, urls, ContentSignals())
        )
        assessment, _, _ = assess_threat(sec, intel, EvidenceGraph())
        self.assertLessEqual(assessment.score, 100)
        self.assertGreater(assessment.score, 50)


if __name__ == "__main__":
    unittest.main()
