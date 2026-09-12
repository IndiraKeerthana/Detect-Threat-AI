"""Tests for the PDF Forensic Investigation Report Generator and API Endpoint."""

import asyncio
import unittest

from app.api.emails import generate_report_pdf
from app.schemas.email import EmailAnalysisResponse
from app.services.pdf_report_generator import (
    compute_evidence_hash,
    format_ist_timestamp,
    generate_forensic_pdf,
    sanitize_text,
)


def get_sample_malicious_analysis() -> dict:
    """Return sample investigation response dict for a high-risk phishing email."""
    return {
        "from": "attacker@phishing-domain.com",
        "to": "victim@company.com",
        "cc": None,
        "bcc": None,
        "subject": "URGENT: Verify your account credentials immediately",
        "date": "2026-09-08T18:30:00Z",
        "message_id": "<20260908183000.12345@phishing-domain.com>",
        "reply_to": "collect@malicious-receiver.com",
        "return_path": "bounce@phishing-domain.com",
        "mime_version": "1.0",
        "content_type": "text/html",
        "received": [
            "from mail.phishing-domain.com (mail.phishing-domain.com [198.51.100.50]) by mx.company.com with ESMTP id abc123xyz for <victim@company.com>; Tue, 08 Sep 2026 18:30:00 +0000"
        ],
        "body_text": "Please verify your account at http://198.51.100.50/login or https://phishing-domain.com/verify?token=gsk_SecretApiKey123456789",
        "body_html": "<p>Please verify</p>",
        "attachments": [
            {
                "filename": "Invoice_Urgent.pdf",
                "content_type": "application/pdf",
                "size": 14250,
            }
        ],
        "relay_analysis": {
            "relay_hops": [
                {
                    "hop_number": 1,
                    "original_header": "from mail.phishing-domain.com ...",
                    "hostnames": ["mail.phishing-domain.com"],
                    "extracted_ips": [
                        {
                            "address": "198.51.100.50",
                            "version": 4,
                            "classification": "public",
                            "is_public_source_candidate": True,
                            "hop_number": 1,
                        }
                    ],
                }
            ],
            "extracted_ips": [
                {
                    "address": "198.51.100.50",
                    "version": 4,
                    "classification": "public",
                    "is_public_source_candidate": True,
                    "hop_number": 1,
                }
            ],
            "probable_source_infrastructure": {
                "address": "198.51.100.50",
                "confidence": "high",
                "reason": "First public relay hop in Received chain.",
            },
            "metadata": {
                "received_header_count": 1,
                "input_header_order": "chronological",
                "reconstructed_order": "chronological",
                "source_selection_scope": "public_only",
            },
        },
        "security_analysis": {
            "summary": "Email contains phishing indicators and suspicious sender alignment failure.",
            "indicators": [
                {
                    "code": "SPF_FAIL",
                    "category": "authentication",
                    "severity": "high",
                    "title": "SPF Authentication Failure",
                    "explanation": "Origin server 198.51.100.50 is not authorized in SPF record for phishing-domain.com.",
                    "evidence": ["198.51.100.50"],
                },
                {
                    "code": "REPLY_TO_MISMATCH",
                    "category": "identity",
                    "severity": "medium",
                    "title": "Reply-To Header Mismatch",
                    "explanation": "Reply-To domain malicious-receiver.com does not match From domain phishing-domain.com.",
                    "evidence": ["collect@malicious-receiver.com"],
                },
                {
                    "code": "SUSPICIOUS_URL_IP_LITERAL",
                    "category": "url",
                    "severity": "critical",
                    "title": "IP-Literal Embedded URL",
                    "explanation": "Embedded link points directly to IP address 198.51.100.50.",
                    "evidence": ["http://198.51.100.50/login"],
                },
            ],
            "authentication": {
                "headers": ["Authentication-Results: mx.company.com; spf=fail; dkim=none; dmarc=fail"],
                "authserv_ids": ["mx.company.com"],
                "results": [],
                "spf": {
                    "method": "spf",
                    "result": "fail",
                    "domain": "phishing-domain.com",
                    "reason": "IP not authorized",
                    "raw": "spf=fail",
                },
                "dkim": {
                    "method": "dkim",
                    "result": "none",
                    "domain": None,
                    "reason": "No signature found",
                    "raw": "dkim=none",
                },
                "dmarc": {
                    "method": "dmarc",
                    "result": "fail",
                    "domain": "phishing-domain.com",
                    "reason": "SPF fail and DKIM absent",
                    "raw": "dmarc=fail",
                },
                "from_domain": "phishing-domain.com",
                "return_path_domain": "phishing-domain.com",
                "reply_to_domain": "malicious-receiver.com",
                "alignment_notes": ["Reply-to domain mismatched"],
            },
            "urls": {
                "urls": [
                    {
                        "url": "http://198.51.100.50/login",
                        "normalized_url": "http://198.51.100.50/login",
                        "domain": "198.51.100.50",
                        "scheme": "http",
                        "associated_domain": "phishing-domain.com",
                        "source": "body_text",
                    },
                    {
                        "url": "https://phishing-domain.com/very/long/path/with/parameters?token=gsk_SecretApiKey123456789&secret=Bearer%20my_secret_token_12345",
                        "normalized_url": "https://phishing-domain.com/very/long/path/with/parameters",
                        "domain": "phishing-domain.com",
                        "scheme": "https",
                        "associated_domain": "phishing-domain.com",
                        "source": "body_text",
                    },
                ],
                "domains": [{"domain": "phishing-domain.com", "source": "from"}],
            },
            "domains": [{"domain": "phishing-domain.com", "source": "from"}],
            "content_signals": {
                "signals": [
                    {
                        "code": "URGENCY_LANGUAGE",
                        "category": "phishing",
                        "severity": "medium",
                        "explanation": "Urgency keyword detected",
                        "evidence": ["URGENT"],
                    }
                ],
                "normalized_text_length": 150,
            },
        },
        "threat_intelligence": {
            "entities": [{"type": "ip", "value": "198.51.100.50", "sources": ["relay"]}],
            "observations": [
                {
                    "provider": "AbuseIPDB",
                    "entity_type": "ip",
                    "entity": "198.51.100.50",
                    "kind": "malicious_host",
                    "status": "success",
                    "data": {
                        "reputation": "high_risk",
                        "asn": "AS65534",
                        "country": "Germany",
                        "city": "Frankfurt",
                    },
                    "evidence": ["Reported 45 times for phishing"],
                    "confidence": "high",
                }
            ],
            "relationships": [
                {
                    "source_type": "ip",
                    "source": "198.51.100.50",
                    "target_type": "domain",
                    "target": "phishing-domain.com",
                    "relationship": "resolves_to",
                    "providers": ["DNS"],
                }
            ],
            "provider_status": [
                {
                    "provider": "AbuseIPDB",
                    "configured": True,
                    "status": "available",
                    "checked": 1,
                },
                {
                    "provider": "VirusTotal",
                    "configured": True,
                    "status": "degraded",
                    "checked": 1,
                    "message": "Rate limit exceeded",
                },
            ],
        },
        "correlations": [
            {
                "code": "IP_DOMAIN_SUSPICIOUS_LINK",
                "relationship": "resolves_to",
                "explanation": "IP 198.51.100.50 associated with high-risk domain phishing-domain.com",
                "evidence": ["198.51.100.50", "phishing-domain.com"],
                "entities": ["198.51.100.50", "phishing-domain.com"],
                "confidence": "high",
                "sources": ["Threat Intel"],
            }
        ],
        "risk_assessment": {
            "score": 85,
            "level": "high",
            "classification": "phishing",
            "threat_types": ["phishing", "bec"],
            "factors": [
                {
                    "code": "SPF_FAIL",
                    "title": "SPF Authentication Failure",
                    "contribution": 35,
                    "severity": "high",
                    "explanation": "SPF validation failed.",
                    "evidence": ["198.51.100.50"],
                },
                {
                    "code": "SUSPICIOUS_URL_IP_LITERAL",
                    "title": "IP-Literal Embedded Link",
                    "contribution": 30,
                    "severity": "critical",
                    "explanation": "Direct IP URL detected.",
                    "evidence": ["http://198.51.100.50/login"],
                },
            ],
            "rationale": "High-risk phishing attempt with failed authentication and suspicious IP links.",
            "confidence": {
                "level": "high",
                "explanation": "Complete header and threat intel coverage.",
                "evidence_count": 4,
                "limitations": ["No sandbox detonation"],
                "factors": [],
            },
        },
        "confidence": {
            "level": "high",
            "explanation": "Complete header and threat intel coverage.",
            "evidence_count": 4,
            "limitations": ["No sandbox detonation"],
            "factors": [],
        },
        "attribution": {
            "status": "infrastructure_only",
            "assessment": "Evidence links origin to German hosting provider AS65534, but does not identify the human threat actor.",
            "confidence": "medium",
            "supporting_evidence": ["198.51.100.50", "AS65534"],
            "limitations": ["Infrastructure attribution only"],
        },
        "attribution_limitations": ["Infrastructure attribution only"],
        "recommended_actions": [
            {
                "code": "CONTAIN_MESSAGE",
                "priority": "urgent",
                "action": "Quarantine email from all user inboxes",
                "rationale": "High risk phishing attempt",
                "evidence": ["Risk Score 85/100"],
            }
        ],
        "investigation_summary": {
            "title": "Phishing Incident Analysis",
            "summary": "High risk phishing attempt targeting user credentials.",
            "risk_level": "high",
            "confidence": "high",
            "key_findings": ["SPF Failure", "IP Link"],
            "limitations": [],
            "source": "deterministic",
        },
        "ai_investigation": {
            "summary": "High risk phishing attempt confirmed by Groq AI Agent.",
            "risk_level": "high",
            "classification": "phishing",
            "confidence": "high",
            "reasoning": "Autonomous analysis confirmed SPF forgery and credential harvesting URLs.",
            "key_findings": [
                {
                    "title": "Credential Harvesting Link",
                    "severity": "critical",
                    "explanation": "IP literal link detected in email body",
                    "evidence": ["http://198.51.100.50/login"],
                }
            ],
            "recommended_actions": ["Quarantine message"],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "Origin infrastructure German host AS65534",
                "confidence": "medium",
                "supporting_evidence": ["198.51.100.50"],
                "limitations": ["Infrastructure only"],
            },
            "evidence": ["http://198.51.100.50/login"],
            "tool_calls": [],
            "iterations": 3,
            "source": "ai_agent",
            "provider": "Groq",
            "model": "llama-3.3-70b-versatile",
        },
    }


def get_sample_benign_analysis() -> dict:
    """Return sample investigation response dict for a low-risk/legitimate email."""
    return {
        "from": "newsletter@trusted-vendor.com",
        "to": "employee@company.com",
        "subject": "Monthly Security Digest - September 2026",
        "date": "2026-09-08T10:00:00Z",
        "message_id": "<digest-20260908@trusted-vendor.com>",
        "received": [
            "from mail.trusted-vendor.com (mail.trusted-vendor.com [203.0.113.10]) by mx.company.com; Tue, 08 Sep 2026 10:00:00 +0000"
        ],
        "relay_analysis": {
            "relay_hops": [
                {
                    "hop_number": 1,
                    "hostnames": ["mail.trusted-vendor.com"],
                    "extracted_ips": [
                        {
                            "address": "203.0.113.10",
                            "version": 4,
                            "classification": "public",
                            "is_public_source_candidate": True,
                            "hop_number": 1,
                        }
                    ],
                }
            ],
            "probable_source_infrastructure": {
                "address": "203.0.113.10",
                "confidence": "high",
                "reason": "Authorized relay server.",
            },
        },
        "security_analysis": {
            "summary": "All authentication checks passed.",
            "indicators": [],
            "authentication": {
                "spf": {"result": "pass", "domain": "trusted-vendor.com"},
                "dkim": {"result": "pass", "domain": "trusted-vendor.com"},
                "dmarc": {"result": "pass", "domain": "trusted-vendor.com"},
            },
            "urls": {"urls": [], "domains": []},
            "content_signals": {"signals": [], "normalized_text_length": 300},
        },
        "risk_assessment": {
            "score": 0,
            "level": "benign",
            "classification": "benign",
            "factors": [],
            "rationale": "Legitimate newsletter email with valid authentication.",
            "confidence": {"level": "high", "explanation": "Passes SPF/DKIM/DMARC", "evidence_count": 3, "limitations": []},
        },
        "confidence": {"level": "high", "explanation": "Passes SPF/DKIM/DMARC", "evidence_count": 3, "limitations": []},
        "attribution": {
            "status": "infrastructure_only",
            "assessment": "Origin verified as trusted vendor mail infrastructure.",
            "confidence": "high",
            "limitations": [],
        },
        "recommended_actions": [],
        "investigation_summary": {
            "title": "Benign Mail Summary",
            "summary": "Legitimate email.",
            "risk_level": "benign",
            "confidence": "high",
        },
        "ai_investigation": {
            "summary": "Legitimate email.",
            "risk_level": "benign",
            "classification": "benign",
            "confidence": "high",
            "reasoning": "Rule-based analysis confirmed pass on all security checks.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "Trusted mail infrastructure",
                "confidence": "high",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": [],
            "tool_calls": [],
            "iterations": 1,
            "source": "ai_agent",
            "provider": "Groq",
            "model": "llama-3.3-70b-versatile",
        },
    }


class TestPdfReportGenerator(unittest.IsolatedAsyncioTestCase):
    def test_pdf_generation_malicious(self):
        """1. Test PDF generation with a malicious/phishing investigation."""
        data = get_sample_malicious_analysis()
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-MALICIOUS")
        self.assertIsNotNone(pdf_bytes)
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_pdf_generation_legitimate(self):
        """2. Test PDF generation with a legitimate/low-risk investigation."""
        data = get_sample_benign_analysis()
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-BENIGN")
        self.assertIsNotNone(pdf_bytes)
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_missing_geolocation(self):
        """3. Test missing geolocation handling."""
        data = get_sample_benign_analysis()
        data["threat_intelligence"] = {"observations": []}
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-NOGEO")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_degraded_threat_intelligence_providers(self):
        """4. Test degraded threat-intelligence providers rendering."""
        data = get_sample_malicious_analysis()
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-DEGRADED")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_ai_live_result(self):
        """5. Test AI live result rendering."""
        data = get_sample_malicious_analysis()
        data["ai_investigation"]["source"] = "ai_agent"
        data["ai_investigation"]["provider"] = "Groq"
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-AILIVE")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_ai_unavailable_rendering(self):
        """6. Test AI unavailable rendering when no autonomous record present."""
        data = get_sample_benign_analysis()
        data["ai_investigation"] = None
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-AIUNAVAIL")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_long_urls_and_text_wrapping(self):
        """7. Test long URLs and long text wrapping without overflow or crash."""
        data = get_sample_malicious_analysis()
        data["subject"] = "A" * 300
        data["security_analysis"]["urls"]["urls"].append({
            "url": "https://example.com/" + "long_path/" * 50 + "?query=" + "xyz" * 50,
            "domain": "example.com",
            "scheme": "https",
            "associated_domain": "example.com",
            "source": "body_text",
        })
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-LONG")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_no_secrets_or_api_keys_leaked(self):
        """8. Test secret and API key redaction in sanitize_text."""
        raw_key = "gsk_SecretApiKey123456789"
        sanitized = sanitize_text(raw_key)
        self.assertNotIn("gsk_SecretApiKey123456789", sanitized)
        self.assertIn("[REDACTED_API_KEY]", sanitized)

        raw_token = "Bearer my_secret_token_12345"
        sanitized_tok = sanitize_text(raw_token)
        self.assertNotIn("my_secret_token_12345", sanitized_tok)
        self.assertIn("[REDACTED_TOKEN]", sanitized_tok)

    def test_no_fabricated_coordinates_or_attacker_location(self):
        """9. Test attribution language and location caveat."""
        data = get_sample_malicious_analysis()
        pdf_bytes = generate_forensic_pdf(data, case_id="CASE-TEST-ATTRIBUTION")
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_ist_timestamp_formatting(self):
        """10. Test IST timestamp formatting function."""
        ts_iso = "2026-09-08T18:30:00Z"
        formatted = format_ist_timestamp(ts_iso)
        self.assertIn("IST", formatted)

    async def test_pdf_endpoint_http_response(self):
        """11. Test FastAPI route handler generate_report_pdf directly."""
        payload_dict = get_sample_malicious_analysis()
        payload = EmailAnalysisResponse.model_validate(payload_dict)
        response = await generate_report_pdf(payload, case_id="CASE-ENDPOINT-TEST")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.media_type, "application/pdf")
        self.assertIn("attachment; filename=", response.headers["Content-Disposition"])
        self.assertTrue(response.body.startswith(b"%PDF-"))
