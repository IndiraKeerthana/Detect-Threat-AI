import unittest
from pathlib import Path

from app.services.authentication_results import parse_authentication_results
from app.services.content_signals import analyze_content_signals
from app.services.email_parser import parse_email
from app.services.security_analysis import analyze_security
from app.services.url_extractor import extract_urls_and_domains
from app.schemas.email import AttachmentMetadata


class SecurityServicesTest(unittest.TestCase):
    def test_authentication_results_parses_spf_dkim_and_dmarc(self) -> None:
        result = parse_authentication_results(
            [
                "Authentication-Results: mx.example; "
                "spf=pass smtp.mailfrom=sender.example; "
                "dkim=fail header.d=signer.example header.s=selector1; "
                "dmarc=pass header.from=sender.example"
            ]
        )

        self.assertEqual(result.authserv_ids, ["mx.example"])
        self.assertEqual(result.spf.result, "pass")
        self.assertEqual(result.spf.domain, "sender.example")
        self.assertEqual(result.dkim.result, "fail")
        self.assertEqual(result.dkim.domain, "signer.example")
        self.assertEqual(result.dkim.selector, "selector1")
        self.assertEqual(result.dmarc.result, "pass")

    def test_authentication_handles_missing_and_multiple_headers(self) -> None:
        self.assertEqual(parse_authentication_results([]).results, [])
        result = parse_authentication_results(
            [
                "mx-a; spf=softfail smtp.mailfrom=one.example",
                "mx-b; dmarc=fail header.from=two.example",
            ]
        )
        self.assertEqual(result.spf.result, "softfail")
        self.assertEqual(result.dmarc.result, "fail")
        self.assertEqual(len(result.headers), 2)

    def test_url_extraction_deduplicates_urls_and_domains(self) -> None:
        result = extract_urls_and_domains(
            body_text="Visit https://Example.com/login. Also see example.com.",
            body_html='<a href="https://example.com/login">login</a>',
        )

        self.assertEqual(len(result.urls), 1)
        self.assertEqual(result.urls[0].domain, "example.com")
        self.assertEqual([item.domain for item in result.domains], ["example.com"])

    def test_url_metadata_handles_http_port_query_and_malformed_values(self) -> None:
        result = extract_urls_and_domains(
            body_text="http://Example.com:8080/path?q=1 and https://bad host"
        )
        self.assertEqual(len(result.urls), 2)
        url = result.urls[0]
        self.assertEqual(url.port, 8080)
        self.assertEqual(url.path, "/path")
        self.assertTrue(url.has_query)
        self.assertFalse(url.is_https)
        self.assertEqual(url.normalized_url, "http://example.com:8080/path?q=1")

    def test_content_signals_are_explainable(self) -> None:
        result = analyze_content_signals(
            subject="Urgent payment",
            body_text="Keep this confidential. Send a wire transfer immediately.",
        )

        codes = {signal.code for signal in result.signals}
        self.assertIn("urgent_action", codes)
        self.assertIn("payment_request", codes)
        self.assertIn("secrecy_or_impersonation", codes)
        self.assertTrue(all(signal.explanation and signal.evidence for signal in result.signals))

    def test_identity_and_attachment_indicators_are_evidence_backed(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "security_signals.eml"
        email = parse_email(fixture.read_bytes()).model_copy(
            update={
                "return_path": "<bounce@other.example>",
                "attachments": [
                    AttachmentMetadata(
                        filename="invoice.exe",
                        content_type="application/x-msdownload",
                        size=10,
                    )
                ],
            }
        )
        analysis = analyze_security(email)
        codes = {item.code for item in analysis.indicators}
        self.assertIn("reply_to_mismatch", codes)
        self.assertIn("return_path_mismatch", codes)
        self.assertIn("suspicious_attachment_type", codes)
        self.assertIn("url_not_https", codes)

    def test_controlled_eml_produces_additive_security_analysis(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "security_signals.eml"
        result = parse_email(fixture.read_bytes())
        analysis = analyze_security(result)

        self.assertEqual(result.subject, "Urgent wire transfer and verification")
        self.assertEqual(analysis.authentication_results.spf.result, "fail")
        self.assertEqual(analysis.authentication_results.dkim.result, "fail")
        self.assertEqual(analysis.authentication_results.dmarc.result, "fail")
        self.assertEqual(analysis.url_analysis.urls[0].domain, "198.51.100.10")
        self.assertTrue(
            {item.code for item in analysis.indicators}
            >= {"spf_fail", "dkim_fail", "dmarc_fail", "url_ip_literal", "reply_to_mismatch"}
        )
