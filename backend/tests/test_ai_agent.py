import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from app.config import Settings
from app.services.ai_agent.agent import (
    AIAnalysisError,
    AIConfigurationError,
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


_PARTS_CACHE = None


def _parts():
    global _PARTS_CACHE
    if _PARTS_CACHE is None:
        email = parse_email((Path(__file__).parent / "fixtures" / "sample.eml").read_bytes())
        security = analyze_security(email)
        intelligence = ThreatIntelligence()
        investigation = analyze_investigation(email, security, intelligence)
        _PARTS_CACHE = (email, security, intelligence, investigation)
    return _PARTS_CACHE


class _FinalProvider:
    def __init__(self, result):
        self.result = result

    def decide(self, context, history, available_tools):
        return ProviderDecision(kind="final", result=self.result)


class AIAgentTest(unittest.TestCase):
    def test_disabled_and_missing_key_raise_configuration_error(self):
        email, security, intelligence, investigation = _parts()
        with self.assertRaises(AIConfigurationError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=False),
            )
        with self.assertRaises(AIConfigurationError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(
                    ai_agent_enabled=True,
                    ai_api_key=None,
                    groq_api_key=None,
                    effective_ai_api_key=None,
                ),
            )

    def test_unavailable_timeout_and_malformed_raise_analysis_error(self):
        email, security, intelligence, investigation = _parts()

        class Broken:
            def decide(self, *args):
                raise TimeoutError("not exposed")

        for provider in (Broken(), _FinalProvider({"bad": True})):
            with self.assertRaises(AIAnalysisError):
                run_ai_investigation(
                    email,
                    security,
                    intelligence,
                    investigation,
                    settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
                    provider=provider,
                )

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

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_1_429_with_retry_after(self, mock_urlopen, mock_sleep):
        """GROQ CASE 1: Provider returns 429 with Retry-After. Instantly moves to fallback without sleep."""
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

        # Primary model (llama-3.3-70b-versatile) returns 429 -> immediately falls back to candidate 2 (llama-3.1-8b-instant) which succeeds
        mock_urlopen.side_effect = [
            HTTPError(
                "https://api.groq.com/openai/v1/chat/completions",
                429,
                "Too Many Requests",
                {"Retry-After": "1.5"},
                fp=None,
            ),
            resp_success,
        ]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
        )
        decision = provider.decide({}, [], ["inspect_url"])
        self.assertEqual(decision.kind, "tool_call")
        self.assertEqual(decision.tool, "inspect_url")
        self.assertEqual(mock_urlopen.call_count, 2)
        # 429 causes immediate fallback without sleeping
        mock_sleep.assert_not_called()
        self.assertEqual(provider.model, "llama-3.3-70b-versatile")

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_2_429_without_retry_after_backoff(self, mock_urlopen, mock_sleep):
        """GROQ CASE 2: Provider returns 429 without Retry-After. Immediately attempts fallback candidate model without sleep."""
        resp_success = MagicMock()
        resp_success.status = 200
        data_bytes = json.dumps({
            "choices": [{
                "message": {
                    "content": json.dumps({"kind": "tool", "tool": "inspect_ip", "arguments": {"ip": "198.51.100.10"}})
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
                {},
                fp=None,
            ),
            resp_success,
        ]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
            base_backoff=0.5,
        )
        decision = provider.decide({}, [], ["inspect_ip"])
        self.assertEqual(decision.kind, "tool_call")
        self.assertEqual(decision.tool, "inspect_ip")
        self.assertEqual(mock_urlopen.call_count, 2)
        mock_sleep.assert_not_called()
        self.assertEqual(provider.model, "llama-3.3-70b-versatile")

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_3_transient_503_retry_succeeds(self, mock_urlopen, mock_sleep):
        """GROQ CASE 3: Provider returns transient 503, retry succeeds, final result is AI-backed."""
        email, security, intelligence, investigation = _parts()
        final_payload = {
            "summary": "AI investigation succeeded after 503 retry",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "503 resolved on retry.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": CONSERVATIVE_ATTRIBUTION,
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": [],
            "tool_calls": [],
            "iterations": 1,
            "source": "ai_agent",
        }
        resp_success = MagicMock()
        resp_success.status = 200
        data_bytes = json.dumps({
            "choices": [{
                "message": {
                    "content": json.dumps({"kind": "final", "result": final_payload})
                }
            }]
        }).encode("utf-8")
        resp_success.__enter__.return_value.read.return_value = data_bytes
        resp_success.__enter__.return_value.status = 200

        mock_urlopen.side_effect = [
            HTTPError(
                "https://api.groq.com/openai/v1/chat/completions",
                503,
                "Service Unavailable",
                {},
                fp=None,
            ),
            resp_success,
        ]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
        )
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=1),
            provider=provider,
        )
        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.iterations, 1)
        self.assertEqual(mock_urlopen.call_count, 2)
        mock_sleep.assert_not_called()

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_4_permanent_authentication_failure_no_retries(self, mock_urlopen, mock_sleep):
        """GROQ CASE 4: Provider returns permanent 401. No pointless repeated retries, raises AIAnalysisError immediately."""
        email, security, intelligence, investigation = _parts()
        mock_urlopen.side_effect = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions",
            401,
            "Unauthorized: Invalid API Key",
            {},
            fp=None,
        )
        provider = create_provider(
            "groq",
            api_key="gsk_invalid_key",
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
        )
        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
                provider=provider,
            )
        # Should fail immediately on attempt 1 without retrying or sleeping
        self.assertEqual(mock_urlopen.call_count, 1)
        mock_sleep.assert_not_called()

    def test_groq_case_5_successful_autonomous_tool_call(self):
        """GROQ CASE 5: Successful autonomous tool call loop with real tool execution."""
        email, security, intelligence, investigation = _parts()
        final_payload = {
            "summary": "Autonomous investigation completed via inspect_domain",
            "risk_level": investigation.risk_assessment.level,
            "classification": investigation.risk_assessment.classification,
            "confidence": investigation.risk_assessment.confidence.level,
            "reasoning": "Domain was verified through registered tool.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": CONSERVATIVE_ATTRIBUTION,
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class AutonomousProvider:
            def __init__(self):
                self.calls = 0

            def decide(self, context, history, available_tools):
                self.calls += 1
                if self.calls == 1:
                    return ProviderDecision(
                        kind="tool_call",
                        tool="inspect_domain",
                        arguments={"domain": "example.com"},
                    )
                return ProviderDecision(kind="final", result=final_payload)

        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
            provider=AutonomousProvider(),
        )
        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].name, "inspect_domain")
        self.assertEqual(result.tool_calls[0].target, "example.com")
        self.assertEqual(result.tool_calls[0].status, "success")
        self.assertEqual(result.tool_calls[0].iteration, 1)

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_6_all_ai_attempts_fail_raises_analysis_error(self, mock_urlopen, mock_sleep):
        """GROQ CASE 6: All AI attempts fail. Raises AIAnalysisError without invoking deterministic fallback."""
        email, security, intelligence, investigation = _parts()
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
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
        )
        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
                provider=provider,
            )

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_case_7_retry_after_extremely_large_bounded_delay(self, mock_urlopen, mock_sleep):
        """GROQ CASE 7: Extremely large Retry-After (3600s) on 429 does NOT sleep and immediately moves to fallback."""
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
                {"Retry-After": "3600"},
                fp=None,
            ),
            resp_success,
        ]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="llama-3.3-70b-versatile",
            timeout_seconds=10.0,
            max_retry_delay=10.0,
        )
        decision = provider.decide({}, [], ["inspect_url"])
        self.assertEqual(decision.kind, "tool_call")
        self.assertEqual(mock_urlopen.call_count, 2)
        # Verify 0 sleep calls occurred
        mock_sleep.assert_not_called()

    def test_native_tool_call_response_and_round_trip(self):
        """Verify native OpenAI-compatible tool_calls:
        assistant tool_calls -> ToolRegistry execution -> role='tool' with matching tool_call_id -> final synthesis."""
        email, security, intelligence, investigation = _parts()

        final_payload = {
            "summary": "Verified domain via native tool call.",
            "risk_level": "medium",
            "classification": "suspicious",
            "confidence": "high",
            "reasoning": "Observed domain is verified via registered tool.",
            "key_findings": [
                {
                    "title": "Domain Checked",
                    "severity": "medium",
                    "explanation": "Native tool executed successfully.",
                    "evidence": ["example.com"],
                }
            ],
            "recommended_actions": ["Monitor domain traffic"],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": CONSERVATIVE_ATTRIBUTION,
                "confidence": "low",
                "supporting_evidence": ["example.com"],
                "limitations": ["Infrastructure evidence does not identify or attribute a human actor."],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class MockNativeProvider:
            def __init__(self):
                self.calls = 0
                self.recorded_messages = []
                self.name = "groq"
                self.model = "openai/gpt-oss-120b"

            def chat_step(self, messages, tools=None):
                self.calls += 1
                self.recorded_messages.append([dict(m) for m in messages])
                if self.calls == 1:
                    assert tools is not None and len(tools) > 0
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_abc123",
                                "type": "function",
                                "function": {
                                    "name": "inspect_domain",
                                    "arguments": json.dumps({"domain": "example.com"}),
                                },
                            }
                        ],
                    }
                # Turn 2: verify round-trip messages received by model
                assert len(messages) >= 4
                assistant_msg = [m for m in messages if m.get("role") == "assistant"][-1]
                assert "tool_calls" in assistant_msg
                tool_msg = [m for m in messages if m.get("role") == "tool"][-1]
                assert tool_msg["tool_call_id"] == "call_abc123"
                assert tool_msg["name"] == "inspect_domain"
                assert "example.com" in tool_msg["content"]

                return {
                    "role": "assistant",
                    "content": "Investigation concluded.",
                    "tool_calls": None,
                }

            def synthesize_final(self, messages, system_prompt=None):
                return final_payload

        mock_p = MockNativeProvider()
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
            provider=mock_p,
        )

        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.model, "openai/gpt-oss-120b")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].name, "inspect_domain")
        self.assertEqual(result.tool_calls[0].target, "example.com")
        self.assertEqual(result.tool_calls[0].status, "success")
        self.assertEqual(result.tool_calls[0].iteration, 1)

    def test_truthful_groq_execution_reporting(self):
        """Verify successful Groq execution truthfully reports source='ai_agent', provider='groq', and model."""
        email, security, intelligence, investigation = _parts()

        final_payload = {
            "summary": "Verified domain via native tool call.",
            "risk_level": "high",
            "classification": "phishing",
            "confidence": "high",
            "reasoning": "Observed phishing domain verified.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": CONSERVATIVE_ATTRIBUTION,
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class MockTruthfulGroqProvider:
            def __init__(self):
                self.name = "groq"
                self.model = "openai/gpt-oss-120b"
                self.calls = 0

            def chat_step(self, messages, tools=None):
                self.calls += 1
                if self.calls == 1:
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_inspect_1",
                                "type": "function",
                                "function": {
                                    "name": "inspect_domain",
                                    "arguments": json.dumps({"domain": "example.com"}),
                                },
                            }
                        ],
                    }
                return {
                    "role": "assistant",
                    "content": "Concluded.",
                    "tool_calls": None,
                }

            def synthesize_final(self, messages, system_prompt=None):
                return final_payload

        provider = MockTruthfulGroqProvider()
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
            provider=provider,
        )

        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.model, "openai/gpt-oss-120b")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].name, "inspect_domain")

    def test_disabled_ai_raises_configuration_error_without_fallback(self):
        """Verify disabled AI raises AIConfigurationError and does not invoke fallback."""
        email, security, intelligence, investigation = _parts()
        with self.assertRaises(AIConfigurationError) as ctx:
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=False),
            )
        self.assertIn("disabled", str(ctx.exception).lower())

    def test_truthful_ai_model_fallback_reporting(self):
        """Verify fallback to another model truthfully reports the fallback model used and NOT the original model."""
        email, security, intelligence, investigation = _parts()

        final_payload = {
            "summary": "Verified domain via fallback model.",
            "risk_level": "high",
            "classification": "phishing",
            "confidence": "high",
            "reasoning": "Fallback model concluded successfully.",
            "key_findings": [],
            "recommended_actions": [],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": CONSERVATIVE_ATTRIBUTION,
                "confidence": "low",
                "supporting_evidence": [],
                "limitations": [],
            },
            "evidence": ["example.com"],
            "tool_calls": [],
            "iterations": 2,
            "source": "ai_agent",
        }

        class MockFallbackProvider:
            def __init__(self):
                self.name = "groq"
                # Simulating that model fallback engaged to openai/gpt-oss-20b
                self.model = "openai/gpt-oss-20b"
                self.calls = 0

            def chat_step(self, messages, tools=None):
                self.calls += 1
                if self.calls == 1:
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_fb_1",
                                "type": "function",
                                "function": {
                                    "name": "inspect_domain",
                                    "arguments": json.dumps({"domain": "example.com"}),
                                },
                            }
                        ],
                    }
                return {
                    "role": "assistant",
                    "content": "Concluded.",
                    "tool_calls": None,
                }

            def synthesize_final(self, messages, system_prompt=None):
                return final_payload

        provider = MockFallbackProvider()
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
            provider=provider,
        )

        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.model, "openai/gpt-oss-20b")
        self.assertNotEqual(result.model, "openai/gpt-oss-120b")
        self.assertEqual(result.iterations, 2)

    def test_native_invalid_tool_name_and_arguments_rejected(self):
        """Verify invalid tool name or entity not in evidence is rejected cleanly without crashing."""
        email, security, intelligence, investigation = _parts()

        class MockInvalidToolsProvider:
            def __init__(self):
                self.calls = 0
                self.model = "openai/gpt-oss-120b"

            def chat_step(self, messages, tools=None):
                self.calls += 1
                if self.calls == 1:
                    # Invalid tool name
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_bad_1",
                                "type": "function",
                                "function": {
                                    "name": "arbitrary_shell_cmd",
                                    "arguments": json.dumps({"cmd": "whoami"}),
                                },
                            }
                        ],
                    }
                elif self.calls == 2:
                    # Invalid argument (entity not in evidence)
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_bad_2",
                                "type": "function",
                                "function": {
                                    "name": "inspect_domain",
                                    "arguments": json.dumps({"domain": "completely-hallucinated.org"}),
                                },
                            }
                        ],
                    }
                return {
                    "role": "assistant",
                    "content": "Concluded with errors noted.",
                    "tool_calls": None,
                }

            def synthesize_final(self, messages, system_prompt=None):
                return {
                    "summary": "Handled invalid tools cleanly",
                    "risk_level": "low",
                    "classification": "benign",
                    "confidence": "low",
                    "reasoning": "Invalid tools failed validation.",
                    "key_findings": [],
                    "recommended_actions": [],
                    "attribution": {
                        "status": "infrastructure_only",
                        "assessment": CONSERVATIVE_ATTRIBUTION,
                        "confidence": "low",
                        "supporting_evidence": [],
                        "limitations": [],
                    },
                    "evidence": [],
                    "tool_calls": [],
                    "iterations": 3,
                    "source": "ai_agent",
                }

        mock_p = MockInvalidToolsProvider()
        result = run_ai_investigation(
            email,
            security,
            intelligence,
            investigation,
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=4),
            provider=mock_p,
        )

        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(len(result.tool_calls), 2)
        self.assertEqual(result.tool_calls[0].name, "arbitrary_shell_cmd")
        self.assertEqual(result.tool_calls[0].status, "error")
        self.assertEqual(result.tool_calls[1].name, "inspect_domain")
        self.assertEqual(result.tool_calls[1].status, "error")

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_groq_400_json_validate_fallback_model(self, mock_urlopen, mock_sleep):
        """Verify HTTP 400 on primary model falls back to secondary model."""
        err_400 = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions",
            400,
            "Bad Request: json_validate_failed",
            {},
            fp=None,
        )
        resp_fallback = MagicMock()
        resp_fallback.status = 200
        resp_fallback.__enter__.return_value.read.return_value = json.dumps({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "fallback model response",
                }
            }]
        }).encode("utf-8")
        resp_fallback.__enter__.return_value.status = 200

        mock_urlopen.side_effect = [err_400, resp_fallback]

        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="openai/gpt-oss-120b",
            timeout_seconds=10.0,
        )
        res = provider.chat_step([{"role": "user", "content": "hello"}])
        self.assertEqual(res["role"], "assistant")
        self.assertEqual(res["content"], "fallback model response")
        # Primary provider.model remains stable as configured
        self.assertEqual(provider.model, "openai/gpt-oss-120b")


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

        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=2),
                provider=Repeater(),
            )

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
        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=5),
                provider=_FinalProvider(hallucinated_payload),
            )

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

        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=3),
                provider=InfiniteUniqueToolsProvider(),
            )

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
        self.assertIn("Mozilla/5.0", headers["User-Agent"])

    def test_missing_groq_api_key_raises(self):
        with self.assertRaises(ProviderError):
            create_provider("groq", api_key="", model="llama-3.3-70b-versatile", timeout_seconds=30.0)
        with self.assertRaises(ProviderError):
            create_provider("groq", api_key=None, model="llama-3.3-70b-versatile", timeout_seconds=30.0)

    def test_groq_settings_effective_key_and_defaults(self):
        s1 = Settings(_env_file=None, groq_api_key="gsk_from_groq_env")
        self.assertEqual(s1.effective_ai_api_key, "gsk_from_groq_env")
        self.assertEqual(s1.ai_provider, "groq")
        self.assertEqual(s1.ai_model, "llama-3.3-70b-versatile")
        self.assertEqual(s1.ai_agent_max_iterations, 4)

        s2 = Settings(_env_file=None, groq_api_key=None, ai_api_key="fallback_key")
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
            model="llama-3.3-70b-versatile",
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
            model="llama-3.3-70b-versatile",
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

    def test_missing_ai_key_does_not_invoke_fallback(self):
        """Rule 1: Missing AI key must raise AIConfigurationError, NEVER invoke fallback."""
        email, security, intelligence, investigation = _parts()
        with self.assertRaises(AIConfigurationError) as ctx:
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(
                    ai_agent_enabled=True,
                    effective_ai_api_key=None,
                    groq_api_key=None,
                    ai_api_key=None,
                ),
            )
        self.assertIn("missing", str(ctx.exception).lower())

    def test_disabled_ai_does_not_invoke_fallback(self):
        """Rule 2: Disabled AI must raise AIConfigurationError, NEVER invoke fallback."""
        email, security, intelligence, investigation = _parts()
        with self.assertRaises(AIConfigurationError) as ctx:
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=False),
            )
        self.assertIn("disabled", str(ctx.exception).lower())

    def test_provider_timeout_does_not_invoke_fallback(self):
        """Rule 3: Provider timeout must raise AIAnalysisError, NEVER invoke fallback."""
        email, security, intelligence, investigation = _parts()

        class TimeoutProvider:
            def decide(self, *args):
                raise TimeoutError("connection timed out")

        with self.assertRaises(AIAnalysisError) as ctx:
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=3),
                provider=TimeoutProvider(),
            )
        self.assertIn("timeout", str(ctx.exception).lower())

    @patch("app.services.ai_agent.provider.urlopen")
    def test_provider_401_does_not_invoke_fallback(self, mock_urlopen):
        """Rule 4: Provider 401 unauthorized must raise AIAnalysisError, NEVER invoke fallback."""
        email, security, intelligence, investigation = _parts()
        mock_urlopen.side_effect = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions",
            401,
            "Unauthorized",
            {},
            fp=None,
        )
        provider = create_provider(
            "groq",
            api_key="gsk_bad_key",
            model="llama-3.3-70b-versatile",
            timeout_seconds=5.0,
        )
        with self.assertRaises(AIAnalysisError) as ctx:
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=3),
                provider=provider,
            )
        self.assertIn("failed", str(ctx.exception).lower())

    @patch("app.services.ai_agent.provider.time.sleep")
    @patch("app.services.ai_agent.provider.urlopen")
    def test_provider_429_does_not_invoke_fallback(self, mock_urlopen, mock_sleep):
        """Rule 5: Provider 429 rate limit exhausting retries must raise AIAnalysisError, NEVER invoke fallback."""
        email, security, intelligence, investigation = _parts()
        mock_urlopen.side_effect = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions",
            429,
            "Rate limit reached",
            {},
            fp=None,
        )
        provider = create_provider(
            "groq",
            api_key="gsk_test",
            model="llama-3.3-70b-versatile",
            timeout_seconds=5.0,
        )
        with self.assertRaises(AIAnalysisError):
            run_ai_investigation(
                email,
                security,
                intelligence,
                investigation,
                settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=2),
                provider=provider,
            )

    def test_successful_ai_executes_normally(self):
        """Rule 6: Successful AI returns source=ai_agent and retains model and provider."""
        email, security, intelligence, investigation = _parts()
        payload = {
            "summary": "Real AI verified investigation",
            "risk_level": "high",
            "classification": "phishing",
            "confidence": "high",
            "reasoning": "Real AI reasoning based on observable evidence.",
            "key_findings": [],
            "recommended_actions": ["Block sender"],
            "attribution": {
                "status": "infrastructure_only",
                "assessment": "Observable infrastructure analysis.",
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
            settings=SimpleNamespace(ai_agent_enabled=True, ai_agent_max_iterations=3),
            provider=_FinalProvider(payload),
        )
        self.assertEqual(result.source, "ai_agent")
        self.assertEqual(result.summary, "Real AI verified investigation")
        self.assertNotEqual(result.source, "deterministic_fallback")

