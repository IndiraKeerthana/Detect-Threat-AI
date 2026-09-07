import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, UploadFile

from app.api.emails import analyze_email
from app.services.intelligence.orchestrator import ThreatIntelligenceOrchestrator
from app.schemas.threat_intelligence import ThreatIntelligence


class EmailRouteTest(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_upload_is_rejected_before_parsing(self) -> None:
        upload = UploadFile(file=io.BytesIO(b"x" * 200), filename="large.eml")
        settings = SimpleNamespace(max_email_size_mb=0.0001)
        with patch("app.api.emails.get_settings", return_value=settings):
            with self.assertRaises(HTTPException) as raised:
                await analyze_email(upload)

        self.assertEqual(raised.exception.status_code, 413)

    async def test_route_returns_full_response_when_provider_fails(self) -> None:
        fixture = (Path(__file__).parent / "fixtures" / "sample.eml").open("rb")
        try:
            upload = UploadFile(file=fixture, filename="sample.eml")
            settings = SimpleNamespace(max_email_size_mb=25.0)
            class BrokenProvider:
                name = "broken"

                def lookup(self, entity_type: str, entity: str) -> None:
                    raise RuntimeError("simulated provider outage")

            def mocked_intelligence(email, relay_analysis, security_analysis):
                return ThreatIntelligenceOrchestrator(providers=[BrokenProvider()]).analyze(
                    email, relay_analysis, security_analysis
                )

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.analyze_threat_intelligence",
                side_effect=mocked_intelligence,
            ):
                response = await analyze_email(upload)
        finally:
            fixture.close()

        self.assertIsNotNone(response.relay_analysis)
        self.assertIsNotNone(response.security_analysis)
        self.assertIsNotNone(response.threat_intelligence)
        self.assertTrue(response.from_)
        self.assertIsNotNone(response.threat_intelligence.entities)
        self.assertIsNotNone(response.threat_intelligence.observations)
        self.assertIsNotNone(response.threat_intelligence.relationships)
        self.assertIsNotNone(response.threat_intelligence.provider_status)
        self.assertEqual(response.threat_intelligence.provider_status[0].status, "error")
