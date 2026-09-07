import unittest
from pathlib import Path
from types import SimpleNamespace

from app.services.ai_agent.agent import (
    build_investigation_context,
    run_ai_investigation,
)
from app.services.ai_agent.provider import ProviderDecision
from app.services.ai_agent.schemas import AIInvestigationResult
from app.services.ai_agent.tools import ToolValidationError, make_tool_registry
from app.services.email_parser import parse_email
from app.services.investigation import analyze_investigation
from app.services.security_analysis import analyze_security
from app.schemas.threat_intelligence import ThreatIntelligence


def _parts():
    email = parse_email((Path(__file__).parent / "fixtures" / "sample.eml").read_bytes())
    security = analyze_security(email)
    # Provider calls are covered by Step 5 tests; keep these unit tests
    # deterministic and offline.
    intelligence = ThreatIntelligence()
    investigation = analyze_investigation(email, security, intelligence)
    return email, security, intelligence, investigation


class _FinalProvider:
    def __init__(self, result):
        self.result = result

    def decide(self, context, history, available_tools):
        return ProviderDecision(kind="final", result=self.result)


class AIAgentTest(unittest.TestCase):
    def test_disabled_and_missing_key_are_deterministic(self):
        email, security, intelligence, investigation = _parts()
        disabled = run_ai_investigation(email, security, intelligence, investigation)
        missing = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_api_key=None),
        )
        self.assertEqual(disabled.source, "deterministic_fallback")
        self.assertEqual(missing.source, "deterministic_fallback")

    def test_unavailable_timeout_and_malformed_fail_closed(self):
        email, security, intelligence, investigation = _parts()

        class Broken:
            def decide(self, *args):
                raise TimeoutError("not exposed")

        for provider in (Broken(), _FinalProvider({"bad": True})):
            result = run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
                provider=provider,
            )
            self.assertEqual(result.source, "deterministic_fallback")

    def test_success_and_safe_attribution(self):
        email, security, intelligence, investigation = _parts()
        payload = {
            "summary": "Evidence-backed result",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "Structured evidence supports this assessment.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "limited_attribution",
                "assessment": "Attributed to an attacker",
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": [],
            "tool_calls": [],
            "iterations": 1,
            "source": "ai_agent",
        }
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
            provider=_FinalProvider(payload),
        )
        self.assertEqual(result.source, "ai_agent")
        self.assertIn("no actor attribution", result.attribution.assessment.lower())

    def test_context_excludes_raw_body_attachments_and_secrets(self):
        email, security, intelligence, investigation = _parts()
        context = build_investigation_context(email, security, intelligence, investigation)
        serialized = repr(context).lower()
        self.assertNotIn("body_text", serialized)
        self.assertNotIn("attachments", serialized)
        self.assertNotIn("authorization", serialized)

    def test_tool_registry_rejects_unknown_and_hallucinated_entities(self):
        registry = make_tool_registry({"entities": [{"type": "domain", "value": "example.com"}]})
        with self.assertRaises(ToolValidationError):
            registry.execute("shell", {"command": "whoami"})
        with self.assertRaises(ToolValidationError):
            registry.execute("inspect_domain", {"entity": "not-in-evidence.example"})

    def test_repeat_protection_and_iteration_bound(self):
        email, security, intelligence, investigation = _parts()

        class Repeater:
            def decide(self, *args):
                return ProviderDecision(
                    kind="tool_call",
                    tool="query_graph",
                    arguments={},
                )

        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=2),
            provider=Repeater(),
        )
        self.assertEqual(result.source, "deterministic_fallback")
        self.assertLessEqual(result.iterations, 2)

    def test_result_schema_forbids_extra_fields(self):
        with self.assertRaises(ValueError):
            AIInvestigationResult.model_validate({"unexpected": "field"})
