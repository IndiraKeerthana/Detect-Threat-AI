import unittest

from app.schemas.email import EmailAnalysisResponse
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import (
    ProviderStatus,
    ThreatEntity,
    ThreatIntelligence,
    ThreatObservation,
    ThreatRelationship,
)
from app.services.investigation import analyze_investigation
from app.services.investigation_summary import InvestigationSummaryService
from app.services.security_analysis import analyze_security


def _email(
    *,
    subject: str = "Hello",
    body: str = "A routine project update.",
    reply_to: str | None = None,
) -> EmailAnalysisResponse:
    return EmailAnalysisResponse(
        from_="sender@example.com",
        to="user@example.net",
        cc=None,
        bcc=None,
        subject=subject,
        date=None,
        message_id=None,
        reply_to=reply_to,
        return_path=None,
        mime_version=None,
        content_type="text/plain",
        received=[],
        body_text=body,
        body_html=None,
        attachments=[],
    )


def _investigate(email: EmailAnalysisResponse, intelligence: ThreatIntelligence | None = None):
    security = analyze_security(email)
    return analyze_investigation(
        email,
        security,
        intelligence or ThreatIntelligence(),
    )


class Step6InvestigationTest(unittest.TestCase):
    def test_benign_message_is_bounded_and_has_routine_action(self) -> None:
        result = _investigate(_email())
        self.assertEqual(result.risk_assessment.level, "benign")
        self.assertEqual(result.risk_assessment.score, 0)
        self.assertEqual(result.risk_assessment.classification, "benign")
        self.assertLessEqual(result.risk_assessment.score, 100)
        self.assertEqual(result.recommended_actions[0].code, "continue_monitoring")

    def test_phishing_is_explainable_and_classified(self) -> None:
        result = _investigate(
            _email(
                subject="Your account will be suspended",
                body="Verify your account and sign in at http://login-example.net/",
            )
        )
        self.assertEqual(result.risk_assessment.classification, "phishing")
        self.assertNotEqual(result.risk_assessment.confidence.level, "high")
        self.assertTrue(result.risk_assessment.factors)
        self.assertTrue(
            any("verify" in evidence.lower() for factor in result.risk_assessment.factors for evidence in factor.evidence)
        )
        self.assertTrue(any(item.code == "contain_message" for item in result.recommended_actions))

    def test_bec_and_mixed_signals_are_distinct_from_confidence(self) -> None:
        email = _email(
            subject="Urgent wire transfer",
            body="Keep this confidential and send a wire transfer to the new bank details.",
            reply_to="executive@lookalike.example",
        )
        result = _investigate(email)
        self.assertEqual(result.risk_assessment.classification, "bec")
        self.assertNotEqual(result.risk_assessment.score, result.risk_assessment.confidence.evidence_count)
        mixed = _investigate(
            email.model_copy(
                update={
                    "body_text": "Urgent: verify your account and send a wire transfer immediately.",
                }
            )
        )
        self.assertEqual(mixed.risk_assessment.classification, "mixed")

    def test_infrastructure_graph_correlates_observable_relationships(self) -> None:
        intelligence = ThreatIntelligence(
            entities=[
                ThreatEntity(type="url", value="https://evil.example/login", sources=["body_text"]),
                ThreatEntity(type="domain", value="evil.example", sources=["url"]),
                ThreatEntity(type="ip", value="8.8.8.8", sources=["received"]),
            ],
            observations=[
                ThreatObservation(
                    provider="geolocation",
                    entity_type="ip",
                    entity="8.8.8.8",
                    kind="location",
                    evidence=["8.8.8.8"],
                    confidence="medium",
                )
            ],
            relationships=[
                ThreatRelationship(
                    source_type="domain",
                    source="evil.example",
                    target_type="ip",
                    target="8.8.8.8",
                    relationship="resolves_to",
                    providers=["dns"],
                )
            ],
        )
        result = _investigate(_email(body="See https://evil.example/login"), intelligence)
        relationships = {item.relationship for item in result.evidence_graph.edges}
        self.assertIn("resolves_to", relationships)
        self.assertIn("observed_by", relationships)
        self.assertIn("url_domain_correlation", {item.code for item in result.correlations})

    def test_provider_failure_lowers_confidence_without_inventing_risk(self) -> None:
        intelligence = ThreatIntelligence(
            provider_status=[
                ProviderStatus(
                    provider="broken",
                    status="error",
                    checked=1,
                    message="Provider unavailable",
                )
            ]
        )
        result = _investigate(_email(), intelligence)
        self.assertEqual(result.risk_assessment.score, 0)
        self.assertEqual(result.risk_assessment.confidence.level, "low")
        self.assertTrue(result.risk_assessment.confidence.limitations)

    def test_provider_infrastructure_corroboration_can_raise_confidence(self) -> None:
        intelligence = ThreatIntelligence(
            entities=[ThreatEntity(type="domain", value="login-example.net", sources=["body_text"])],
            observations=[
                ThreatObservation(
                    provider="virustotal",
                    entity_type="domain",
                    entity="login-example.net",
                    kind="reputation",
                    data={"reputation": -20, "last_analysis_stats": {"malicious": 8}},
                    evidence=["login-example.net"],
                    confidence="high",
                )
            ],
        )
        result = _investigate(
            _email(
                subject="Your account will be suspended",
                body="Verify your account at http://login-example.net/",
            ),
            intelligence,
        )
        self.assertEqual(result.risk_assessment.confidence.level, "high")

    def test_recommended_evidence_actions_are_specific_and_evidence_backed(self) -> None:
        result = _investigate(
            _email(
                subject="Urgent payment and account verification",
                body=(
                    "Verify your account and send a wire transfer immediately "
                    "at http://login-example.net/"
                ),
            )
        )
        actions = {item.code: item for item in result.recommended_actions}
        for code in {
            "investigate_suspicious_url",
            "verify_financial_request",
            "secure_credentials",
        }:
            self.assertIn(code, actions)
            item = actions[code]
            self.assertTrue(
                all((item.title, item.reason, item.source, item.evidence, item.priority, item.rationale))
            )
        self.assertEqual(
            actions["investigate_suspicious_url"].action,
            "Do not open the link; investigate the destination in a safe environment and verify it through a trusted channel.",
        )

    def test_provider_metadata_is_merged_safely_onto_observable_nodes(self) -> None:
        intelligence = ThreatIntelligence(
            entities=[ThreatEntity(type="ip", value="8.8.8.8", sources=["received"])],
            observations=[
                ThreatObservation(
                    provider="geolocation",
                    entity_type="ip",
                    entity="8.8.8.8",
                    kind="geolocation",
                    data={
                        "abuseConfidenceScore": 12,
                        "asn": "AS15169",
                        "isp": "Google LLC",
                        "country_code": "US",
                        "latitude": 37.4,
                        "dnssec": {"delegationSigned": True},
                        "secret": "must-not-be-copied",
                    },
                    confidence="high",
                )
            ],
        )
        result = _investigate(_email(), intelligence)
        node = next(item for item in result.evidence_graph.nodes if item.value == "8.8.8.8")
        self.assertEqual(node.properties["abuseConfidenceScore"], 12)
        self.assertEqual(node.properties["asn"], "AS15169")
        self.assertEqual(node.properties["country_code"], "US")
        self.assertEqual(node.properties["provider"], "geolocation")
        self.assertNotIn("secret", node.properties)

    def test_mixed_provider_confidence_is_not_collapsed_into_risk(self) -> None:
        intelligence = ThreatIntelligence(
            observations=[
                ThreatObservation(
                    provider="one",
                    entity_type="domain",
                    entity="example.com",
                    kind="reputation",
                    confidence="high",
                ),
                ThreatObservation(
                    provider="two",
                    entity_type="domain",
                    entity="example.com",
                    kind="registration",
                    confidence="low",
                ),
            ]
        )
        result = _investigate(_email(), intelligence)
        self.assertEqual(result.risk_assessment.score, 0)
        self.assertEqual(result.risk_assessment.confidence.level, "medium")

    def test_attribution_is_explicitly_limited(self) -> None:
        result = _investigate(_email(body="See https://example.org"))
        self.assertEqual(result.attribution.status, "infrastructure_only")
        self.assertTrue(result.attribution.limitations)
        self.assertTrue(any("actor" in item.lower() for item in result.attribution.limitations))
        self.assertEqual(result.investigation_summary.source, "deterministic")

    def test_structured_confidence_sources_graph_and_actions_are_rich(self) -> None:
        result = _investigate(
            _email(
                subject="Your account will be suspended",
                body="Verify your account at http://login-example.net/",
            )
        )
        self.assertTrue(all(item.source and item.sources for item in result.risk_assessment.factors))
        self.assertEqual(
            {item.category for item in result.risk_assessment.confidence.factors},
            {"authentication", "content", "url", "infrastructure", "reputation", "registration/DNS", "correlation"},
        )
        self.assertTrue(any(node.type == "email" for node in result.evidence_graph.nodes))
        self.assertTrue(all(action.title and action.reason and action.source for action in result.recommended_actions))

    def test_renderer_fallback_logs_no_renderer_payload(self) -> None:
        result = _investigate(_email())
        renderer = InvestigationSummaryService(
            lambda *_: (_ for _ in ()).throw(RuntimeError("secret body"))
        )
        summary = renderer.summarize(
            result.risk_assessment, result.attribution, result.evidence_graph
        )
        self.assertEqual(summary.source, "fallback")

    def test_suspicious_provider_score_stays_below_hard_maximum(self) -> None:
        result = _investigate(
            _email(),
            ThreatIntelligence(
                observations=[
                    ThreatObservation(
                        provider="reputation",
                        entity_type="domain",
                        entity="example.com",
                        kind="reputation",
                        data={"abuseConfidenceScore": 80},
                        evidence=["example.com"],
                        confidence="high",
                    )
                ]
            ),
        )
        self.assertEqual(result.risk_assessment.classification, "suspicious")
        self.assertLess(result.risk_assessment.score, 100)
