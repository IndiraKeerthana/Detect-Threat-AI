import asyncio
import io
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, UploadFile

from app.api.emails import analyze_email
from app.services.ai_agent.agent import run_ai_investigation
from app.services.ai_agent.schemas import (
    AIAttribution,
    AIFinding,
    AIInvestigationResult,
    AIToolCall,
)
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
        self.assertIsNotNone(response.investigation)
        self.assertIsNotNone(response.risk_assessment)
        self.assertIsNotNone(response.evidence_graph)
        self.assertTrue(response.recommended_actions)

    async def test_ai_investigation_executed_in_worker_thread(self) -> None:
        """Verify run_ai_investigation executes on a separate worker thread off the event loop."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample.eml"
        with open(fixture_path, "rb") as fixture:
            upload = UploadFile(file=fixture, filename="sample.eml")
            event_loop_thread = threading.current_thread()
            captured_threads: list[threading.Thread] = []

            original_run_ai = run_ai_investigation

            def thread_recording_spy(*args, **kwargs):
                captured_threads.append(threading.current_thread())
                return original_run_ai(*args, **kwargs)

            settings = SimpleNamespace(
                max_email_size_mb=25.0,
                ai_agent_enabled=False,
            )

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.run_ai_investigation", side_effect=thread_recording_spy
            ):
                response = await analyze_email(upload)

            self.assertEqual(len(captured_threads), 1)
            ai_thread = captured_threads[0]
            # Must NOT execute on the event loop thread
            self.assertNotEqual(ai_thread, event_loop_thread)
            self.assertIsNotNone(response.ai_investigation)
            self.assertEqual(response.ai_investigation.source, "deterministic_fallback")

    async def test_ai_investigation_uses_asyncio_to_thread(self) -> None:
        """Verify asyncio.to_thread is invoked with run_ai_investigation and valid arguments."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample.eml"
        with open(fixture_path, "rb") as fixture:
            upload = UploadFile(file=fixture, filename="sample.eml")
            settings = SimpleNamespace(max_email_size_mb=25.0, ai_agent_enabled=False)

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.asyncio.to_thread", wraps=asyncio.to_thread
            ) as mock_to_thread:
                response = await analyze_email(upload)

            mock_to_thread.assert_called_once()
            call_func = mock_to_thread.call_args[0][0]
            self.assertEqual(call_func, run_ai_investigation)
            self.assertIsNotNone(response.ai_investigation)

    async def test_ai_investigation_successful_ai_agent_carried_through(self) -> None:
        """Verify successful AI investigation with source=ai_agent, iterations, and tool_calls is preserved."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample.eml"
        with open(fixture_path, "rb") as fixture:
            upload = UploadFile(file=fixture, filename="sample.eml")
            ai_result = AIInvestigationResult(
                summary="AI investigation confirmed suspicious URL",
                risk_level="high",
                classification="phishing",
                confidence="high",
                reasoning="Evidence-backed reasoning.",
                key_findings=[
                    AIFinding(
                        title="Suspicious Link",
                        severity="high",
                        explanation="Link points to non-public IP",
                        evidence=["http://198.51.100.10/verify"],
                    )
                ],
                recommended_actions=["Block URL"],
                attribution=AIAttribution(
                    status="infrastructure_only",
                    assessment="The evidence supports identification of suspicious infrastructure.",
                    confidence="low",
                    supporting_evidence=["http://198.51.100.10/verify"],
                    limitations=["Infrastructure evidence does not identify or attribute a human actor."],
                ),
                evidence=["http://198.51.100.10/verify"],
                tool_calls=[
                    AIToolCall(
                        name="inspect_url",
                        arguments={"url": "http://198.51.100.10/verify"},
                        result_summary="inspect_url returned 2 field(s).",
                        target="http://198.51.100.10/verify",
                        iteration=1,
                        status="success",
                    )
                ],
                iterations=2,
                source="ai_agent",
            )
            settings = SimpleNamespace(max_email_size_mb=25.0)

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.run_ai_investigation", return_value=ai_result
            ):
                response = await analyze_email(upload)

            self.assertIsNotNone(response.ai_investigation)
            self.assertEqual(response.ai_investigation.source, "ai_agent")
            self.assertEqual(response.ai_investigation.iterations, 2)
            self.assertEqual(len(response.ai_investigation.tool_calls), 1)
            self.assertEqual(response.ai_investigation.tool_calls[0].name, "inspect_url")
            self.assertEqual(response.ai_investigation.tool_calls[0].status, "success")
            self.assertIsNotNone(response.relay_analysis)
            self.assertIsNotNone(response.security_analysis)
            self.assertIsNotNone(response.threat_intelligence)
            self.assertIsNotNone(response.investigation)
            self.assertIsNotNone(response.evidence_graph)

    async def test_ai_investigation_deterministic_fallback_carried_through(self) -> None:
        """Verify deterministic fallback structure is preserved on provider failure."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample.eml"
        with open(fixture_path, "rb") as fixture:
            upload = UploadFile(file=fixture, filename="sample.eml")
            fallback_result = AIInvestigationResult(
                summary="Deterministic fallback summary",
                risk_level="medium",
                classification="suspicious",
                confidence="medium",
                reasoning="Deterministic rationale.",
                key_findings=[],
                recommended_actions=[],
                attribution=AIAttribution(
                    status="infrastructure_only",
                    assessment="Infrastructure only.",
                    confidence="low",
                    supporting_evidence=[],
                    limitations=[],
                ),
                evidence=[],
                tool_calls=[],
                iterations=0,
                source="deterministic_fallback",
            )
            settings = SimpleNamespace(max_email_size_mb=25.0)

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.run_ai_investigation", return_value=fallback_result
            ):
                response = await analyze_email(upload)

            self.assertIsNotNone(response.ai_investigation)
            self.assertEqual(response.ai_investigation.source, "deterministic_fallback")
            self.assertEqual(response.ai_investigation.iterations, 0)
            self.assertEqual(response.ai_investigation.tool_calls, [])

    async def test_ai_investigation_exception_fails_closed_safely(self) -> None:
        """Verify route handles unhandled worker thread exceptions gracefully without crashing."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample.eml"
        with open(fixture_path, "rb") as fixture:
            upload = UploadFile(file=fixture, filename="sample.eml")
            settings = SimpleNamespace(max_email_size_mb=25.0)

            with patch("app.api.emails.get_settings", return_value=settings), patch(
                "app.api.emails.run_ai_investigation",
                side_effect=RuntimeError("unexpected worker thread failure"),
            ):
                response = await analyze_email(upload)

            self.assertIsNone(response.ai_investigation)
            self.assertIsNotNone(response.security_analysis)
            self.assertIsNotNone(response.investigation)
            self.assertIsNotNone(response.risk_assessment)
