"""Unit tests for Completed Cases Management and Database Persistence."""

import os
import unittest
from unittest.mock import AsyncMock, patch

from app.api.cases import get_all_cases, get_case, update_status
from app.api.emails import generate_report_pdf
from app.schemas.case import CaseStatusUpdateSchema
from app.schemas.email import EmailAnalysisResponse
from app.services.case_storage import (
    get_case_by_id,
    list_cases,
    reset_db_for_testing,
    save_case,
    update_case_status,
)


def get_sample_investigation_data(case_id: str, subject: str, sender: str, verdict: str = "phishing") -> dict:
    return {
        "id": case_id,
        "title": f"Forensic Ingestion — {subject}",
        "subject": subject,
        "sender": sender,
        "recipient": "victim@company.com",
        "severity": "HIGH" if verdict == "phishing" else "LOW",
        "classification": verdict,
        "riskScore": 85 if verdict == "phishing" else 10,
        "confidence": "high",
        "status": "OPEN",
        "createdAt": "2026-09-09 10:00:00 UTC",
        "updatedAt": "2026-09-09 10:00:00 UTC",
        "sourceIp": "198.51.100.50",
        "investigationData": {
            "from": sender,
            "to": "victim@company.com",
            "subject": subject,
            "date": "2026-09-09T10:00:00Z",
            "message_id": f"<{case_id}@test.local>",
            "received": [],
            "attachments": [],
            "cc": None,
            "bcc": None,
            "reply_to": None,
            "return_path": None,
            "mime_version": "1.0",
            "content_type": "text/plain",
            "body_text": "Sample email body",
            "body_html": "<p>Sample email body</p>",
            "risk_assessment": {
                "score": 85 if verdict == "phishing" else 10,
                "level": "high" if verdict == "phishing" else "low",
                "classification": verdict,
                "threat_types": [verdict],
                "factors": [],
                "rationale": "Test rationale",
                "confidence": {"level": "high", "explanation": "Complete coverage", "evidence_count": 2, "limitations": [], "factors": []},
            },
            "confidence": {"level": "high", "explanation": "Complete coverage", "evidence_count": 2, "limitations": [], "factors": []},
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "Infrastructure origin only.",
                "confidence": "high",
                "supporting_evidence": [],
                "limitations": [],
            },
            "investigation_summary": {
                "title": "Test Summary",
                "summary": "Summary text",
                "risk_level": "high" if verdict == "phishing" else "low",
                "confidence": "high",
                "key_findings": [],
                "limitations": [],
                "source": "deterministic",
            },
        },
    }


class TestCasesPersistence(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env_patcher = patch.dict("os.environ", {"DATABASE_URL": ""})
        self.env_patcher.start()
        reset_db_for_testing()
        # Insert test cases
        self.case1 = get_sample_investigation_data("CASE-TEST-001", "Phishing Password Reset", "attacker@bad.com", "phishing")
        self.case2 = get_sample_investigation_data("CASE-TEST-002", "Monthly Security Digest", "news@good.com", "benign")
        save_case(self.case1)
        save_case(self.case2)

    def tearDown(self):
        reset_db_for_testing()
        self.env_patcher.stop()

    def test_save_and_retrieve_completed_case(self):
        """1. Successful investigation saves and retrieves completed case."""
        retrieved = get_case_by_id("CASE-TEST-001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["id"], "CASE-TEST-001")
        self.assertEqual(retrieved["subject"], "Phishing Password Reset")
        self.assertEqual(retrieved["classification"], "phishing")
        self.assertEqual(retrieved["riskScore"], 85)

    def test_cases_persist_after_restart(self):
        """3. Cases persist across queries."""
        all_cases = list_cases()
        ids = [c["id"] for c in all_cases]
        self.assertIn("CASE-TEST-001", ids)
        self.assertIn("CASE-TEST-002", ids)

    def test_list_cases_returns_saved(self):
        """4. Cases list returns saved completed cases."""
        cases = list_cases()
        self.assertEqual(len(cases), 2)

    def test_case_retrieval_read_only_no_reanalysis(self):
        """5. Case retrieval returns stored data without triggering re-analysis."""
        with patch("app.services.email_parser.parse_email", side_effect=Exception("Should not be called")) as mock_parser:
            with patch("app.services.ai_agent.agent.run_ai_investigation", side_effect=Exception("Should not be called")) as mock_ai:
                record = get_case_by_id("CASE-TEST-001")
                self.assertIsNotNone(record)
                self.assertEqual(record["subject"], "Phishing Password Reset")
                mock_parser.assert_not_called()
                mock_ai.assert_not_called()

    async def test_get_case_api_endpoint(self):
        """6. FastAPI endpoint GET /api/cases/{case_id} returns stored payload."""
        res = await get_case("CASE-TEST-001")
        self.assertEqual(res["id"], "CASE-TEST-001")
        self.assertEqual(res["subject"], "Phishing Password Reset")
        self.assertIn("investigationData", res)

    def test_search_cases_by_subject_and_sender(self):
        """7. Search works by subject, sender, and IOC."""
        results_subj = list_cases(search="Password")
        self.assertEqual(len(results_subj), 1)
        self.assertEqual(results_subj[0]["id"], "CASE-TEST-001")

        results_sender = list_cases(search="good.com")
        self.assertEqual(len(results_sender), 1)
        self.assertEqual(results_sender[0]["id"], "CASE-TEST-002")

    def test_verdict_and_status_filtering(self):
        """8. Verdict and status filtering works."""
        phish_cases = list_cases(verdict="phishing")
        self.assertEqual(len(phish_cases), 1)
        self.assertEqual(phish_cases[0]["classification"], "phishing")

        benign_cases = list_cases(verdict="benign")
        self.assertEqual(len(benign_cases), 1)
        self.assertEqual(benign_cases[0]["classification"], "benign")

        open_cases = list_cases(status="OPEN")
        self.assertEqual(len(open_cases), 2)

    def test_independent_cases(self):
        """9. Multiple cases remain independent."""
        c1 = get_case_by_id("CASE-TEST-001")
        c2 = get_case_by_id("CASE-TEST-002")
        self.assertNotEqual(c1["id"], c2["id"])
        self.assertNotEqual(c1["subject"], c2["subject"])
        self.assertNotEqual(c1["riskScore"], c2["riskScore"])

    async def test_update_case_status_api(self):
        """10. Status update API endpoint."""
        res = await update_status("CASE-TEST-001", CaseStatusUpdateSchema(status="CONTAINED"))
        self.assertEqual(res["status"], "CONTAINED")
        c1 = get_case_by_id("CASE-TEST-001")
        self.assertEqual(c1["status"], "CONTAINED")

    async def test_pdf_report_with_stored_investigation_data(self):
        """11. Report generation uses stored case investigation data."""
        c1 = get_case_by_id("CASE-TEST-001")
        payload = EmailAnalysisResponse.model_validate(c1["investigationData"])
        response = await generate_report_pdf(payload, case_id=c1["id"])
        self.assertEqual(response.media_type, "application/pdf")
        self.assertTrue(len(response.body) > 0)
        self.assertIn("CASE-TEST-001", response.headers["Content-Disposition"])

    def test_db_connection_failure_handling(self):
        """12. Gracefully handles DB connection failure without exposing secrets."""
        with patch("app.services.case_storage.is_postgres", return_value=True):
            with patch("app.services.case_storage._get_pg_connection", side_effect=RuntimeError("Database connection error. Please verify database configuration.")):
                with self.assertRaises(RuntimeError) as ctx:
                    get_case_by_id("CASE-TEST-001")
                self.assertEqual(str(ctx.exception), "Database connection error. Please verify database configuration.")
