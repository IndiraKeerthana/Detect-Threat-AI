import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from app.config import Settings
from app.services.ai_agent.agent import (
    CONSERVATIVE_ATTRIBUTION,
    build_investigation_context,
    run_ai_investigation,
)
from app.services.ai_agent.provider import (
    OpenAICompatibleProvider,
    ProviderDecision,
    ProviderError,
    _clean_and_parse_json,
    create_provider,
)
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
        disabled = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=False),
        )
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
        self.assertEqual(result.attribution.assessment, CONSERVATIVE_ATTRIBUTION)
        self.assertEqual(result.attribution.status, "infrastructure_only")

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

    def test_autonomous_multi_turn_investigation_loop(self):
        email, security, intelligence, investigation = _parts()
        final_payload = {
            "summary": "Multi-turn investigation complete",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "Investigated domain via tool then finalized.",
            "key_findings": [
                {
                    "title": "Domain Check",
                    "severity": "info",
                    "explanation": "Domain was checked.",
                    "evidence": ["example.com"],
                }
            ],
            "recommended_actions": ["Monitor domain"],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "Infrastructure observables only.",
                "confidence": "low",
                "supporting_evidence": ["example.com"],
                "limitations": [],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class MockMultiTurnProvider:
            def __init__(self):
                self.call_count = 0
                self.history_recorded = []

            def decide(self, context, history, available_tools):
                self.call_count += 1
                self.history_recorded.append(list(history))
                if self.call_count == 1:
                    assert any("inspect_domain" in t for t in available_tools)
                    # Iteration 1: Request a valid tool
                    return ProviderDecision(
                        kind="tool_call",
                        tool="inspect_domain",
                        arguments={"domain": "example.com"},
                    )
                # Iteration 2: Tool result received in history, return final report
                assert len(history) == 1
                assert history[0]["tool"] == "inspect_domain"
                return ProviderDecision(kind="final", result=final_payload)

        provider = MockMultiTurnProvider()
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
            provider=provider,
        )

        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.tool_calls), 1)
        tool_call = result.tool_calls[0]
        self.assertEqual(tool_call.name, "inspect_domain")
        self.assertEqual(tool_call.arguments, {"domain": "example.com"})
        self.assertEqual(tool_call.status, "success")
        self.assertEqual(tool_call.iteration, 1)
        self.assertTrue(bool(tool_call.result_summary))
        # Ensure no secrets in tool calls
        self.assertNotIn("secret", repr(tool_call).lower())
        self.assertNotIn("key", repr(tool_call).lower())
        self.assertEqual(len(result.key_findings), 1)
        self.assertEqual(len(result.recommended_actions), 1)

    def test_invalid_tool_name_recorded_as_error_and_recovered(self):
        email, security, intelligence, investigation = _parts()
        final_payload = {
            "summary": "Recovered from invalid tool",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "Recovered and finalized.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "No actor attribution.",
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class InvalidToolProvider:
            def __init__(self):
                self.calls = 0

            def decide(self, context, history, available_tools):
                self.calls += 1
                if self.calls == 1:
                    return ProviderDecision(
                        kind="tool_call",
                        tool="unauthorized_tool",
                        arguments={"foo": "bar"},
                    )
                assert len(history) == 1
                assert "error" in history[0]
                return ProviderDecision(kind="final", result=final_payload)

        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
            provider=InvalidToolProvider(),
        )
        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].status, "error")

    def test_hallucinated_url_in_evidence_rejected_to_fallback(self):
        email, security, intelligence, investigation = _parts()
        hallucinated_payload = {
            "summary": "Hallucinated link",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "Fabricated evidence link.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "No actor attribution.",
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": ["http://hallucinated-attacker-domain-never-seen.com/bad"],
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
            provider=_FinalProvider(hallucinated_payload),
        )
        self.assertEqual(result.source, "deterministic_fallback")

    def test_iteration_limit_enforced_without_repeats(self):
        email, security, intelligence, investigation = _parts()

        class InfiniteUniqueToolsProvider:
            def __init__(self):
                self.call = 0

            def decide(self, context, history, available_tools):
                self.call += 1
                return ProviderDecision(
                    kind="tool_call",
                    tool="explain_indicator",
                    arguments={"code": f"CODE_{self.call}"},
                )

        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=3),
            provider=InfiniteUniqueToolsProvider(),
        )
        self.assertEqual(result.source, "deterministic_fallback")
        self.assertEqual(result.iterations, 3)
        self.assertEqual(len(result.tool_calls), 3)

    def test_groq_provider_configuration(self):
        provider = create_provider(
            "groq",
            api_key="gsk_test_secret_key",
            model="llama-3.3-70b-versatile",
            timeout_seconds=45.0,
        )
        self.assertIsInstance(provider, OpenAICompatibleProvider)
        self.assertEqual(provider.endpoint, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(provider.model, "llama-3.3-70b-versatile")
        headers = provider._headers()
        self.assertEqual(headers["Authorization"], "Bearer gsk_test_secret_key")
        self.assertEqual(headers["User-Agent"], "DetectThreatAI/1.0")

    def test_missing_groq_api_key_raises(self):
        with self.assertRaises(ProviderError):
            create_provider("groq", api_key="", model="llama-3.3-70b-versatile", timeout_seconds=30.0)
        with self.assertRaises(ProviderError):
            create_provider("groq", api_key=None, model="llama-3.3-70b-versatile", timeout_seconds=30.0)

    def test_groq_settings_effective_key_and_defaults(self):
        s1 = Settings(groq_api_key="gsk_from_groq_env")
        self.assertEqual(s1.effective_ai_api_key, "gsk_from_groq_env")
        self.assertEqual(s1.ai_provider, "groq")
        self.assertEqual(s1.ai_model, "llama-3.3-70b-versatile")
        self.assertEqual(s1.ai_agent_max_iterations, 4)

        s2 = Settings(groq_api_key=None, ai_api_key="fallback_key")
        self.assertEqual(s2.effective_ai_api_key, "fallback_key")

    def test_groq_json_parsing_and_markdown_cleaning(self):
        raw_fenced = '```json\n{"kind": "tool", "tool": "inspect_url", "arguments": {"url": "http://test.com"}}\n```'
        parsed = _clean_and_parse_json(raw_fenced)
        self.assertEqual(parsed["tool"], "inspect_url")

        raw_trailing = '{"kind": "tool", "tool": "inspect_ip", "arguments": {"ip": "1.2.3.4",},}'
        parsed_trailing = _clean_and_parse_json(raw_trailing)
        self.assertEqual(parsed_trailing["tool"], "inspect_ip")

    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_429_respects_retry_and_backoff(self, mock_urlopen):
        resp_success = MagicMock()
        resp_success.status = 200
        data_bytes = json.dumps({
            "choices": [{
                "message": {
                    "content": json.dumps({"kind": "tool", "tool": "inspect_url", "arguments": {"url": "http://198.51.100.10/verify"}})
                }
            }]
        }).encode("utf-8")
        resp_success.__enter__.return_value.read.return_value = data_bytes
        resp_success.__enter__.return_value.status = 200

        mock_urlopen.side_effect = [
            HTTPError(
                "https://api.groq.com/openai/v1/chat/completions",
                429,
                "Too Many Requests",
                {"Retry-After": "0.1"},
                fp=None,
            ),
            resp_success,
        ]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="groq/compound-mini",
            timeout_seconds=10.0,
        )
        decision = provider.decide({}, [], ["inspect_url"])
        self.assertEqual(decision.kind, "tool_call")
        self.assertEqual(decision.tool, "inspect_url")
        self.assertEqual(mock_urlopen.call_count, 2)

    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_500_retries_and_falls_back(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions",
            500,
            "Internal Server Error",
            {},
            fp=None,
        )
        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="groq/compound-mini",
            timeout_seconds=10.0,
        )
        with self.assertRaises(ProviderError):
            provider.decide({}, [], ["inspect_url"])
        self.assertEqual(mock_urlopen.call_count, 3)

    def test_attribution_sanitizes_unsupported_inferences(self):
        email, security, intelligence, investigation = _parts()
        for bad_assessment in [
            "This suggests a low-skill phishing kit rather than a sophisticated APT.",
            "Attributed to Russian state-sponsored criminal group CozyBear.",
            "The attacker exhibits novice skill level with high intent to steal credentials.",
            "Associated with an APT syndicate.",
        ]:
            payload = {
                "summary": "Result with bad attribution",
                "risk_level": "high",
                "classification": "phishing",
                "confidence": "high",
                "reasoning": "Reasoning",
                "key_findings": [],
                "recommended_actions": [],
                "attribution": {
                    "status": "infrastructure_only",
                    "assessment": bad_assessment,
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
            self.assertEqual(result.attribution.assessment, CONSERVATIVE_ATTRIBUTION)
            self.assertEqual(result.attribution.status, "infrastructure_only")
