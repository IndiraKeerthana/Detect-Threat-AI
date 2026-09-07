import json
import urllib.error
import unittest
from unittest.mock import MagicMock, patch

from app.schemas.email import EmailAnalysisResponse
from app.services.intelligence.orchestrator import ThreatIntelligenceOrchestrator
from app.services.intelligence.providers import (
    AbuseIPDBProvider,
    DNSProvider,
    IPGeolocationProvider,
    LocalIPClassifierProvider,
    RDAPProvider,
    VirusTotalProvider,
)


def _email() -> EmailAnalysisResponse:
    return EmailAnalysisResponse(
        from_="sender@example.com",
        to=None,
        cc=None,
        bcc=None,
        subject="test",
        date=None,
        message_id=None,
        reply_to=None,
        return_path=None,
        mime_version=None,
        content_type=None,
        received=[],
        body_text="See https://example.com/login",
        body_html=None,
        attachments=[],
    )


def _response(payload: object, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status = status
    response.read.return_value = json.dumps(payload).encode()
    response.__enter__.return_value = response
    return response


class ThreatIntelligenceProvidersTest(unittest.TestCase):
    def test_local_classification_handles_public_private_and_invalid(self) -> None:
        provider = LocalIPClassifierProvider()
        self.assertEqual(provider.classify("8.8.8.8")["classification"], "public")
        self.assertEqual(provider.classify("10.0.0.1")["classification"], "private")
        self.assertIsNone(provider.classify("not-an-ip"))

    def test_abuseipdb_success_and_missing_key_do_not_call_network(self) -> None:
        payload = {"data": {"abuseConfidenceScore": 42, "countryCode": "US"}}
        with patch("urllib.request.urlopen", return_value=_response(payload)) as mocked:
            result = AbuseIPDBProvider("secret").collect([("ip", "8.8.8.8")])
        self.assertEqual(result.status, "available")
        self.assertEqual(result.observations[0].data["abuseConfidenceScore"], 42)
        with patch("urllib.request.urlopen") as mocked:
            skipped = AbuseIPDBProvider(None).collect([("ip", "8.8.8.8")])
        self.assertEqual(skipped.status, "skipped")
        mocked.assert_not_called()

    def test_reputation_provider_failure_and_malformed_are_isolated(self) -> None:
        with patch("urllib.request.urlopen", side_effect=OSError):
            failed = VirusTotalProvider("secret").collect([("ip", "8.8.8.8")])
        self.assertEqual(failed.status, "error")
        with patch("urllib.request.urlopen", return_value=_response({"data": {}})):
            malformed = VirusTotalProvider("secret").collect([("ip", "8.8.8.8")])
        self.assertEqual(malformed.status, "error")

    def test_ip_geolocation_public_success_normalizes_and_relates(self) -> None:
        payload = {
            "ip": "8.8.8.8",
            "location": {
                "country_code2": "US",
                "country_name": "United States",
                "state_prov": "California",
                "city": "Mountain View",
                "latitude": "37.4056",
                "longitude": "-122.0775",
            },
            "time_zone": {"name": "America/Los_Angeles"},
            "asn": {
                "as_number": "AS15169",
                "organization": "Google LLC",
            },
            "isp": "Google LLC",
        }
        with patch("urllib.request.urlopen", return_value=_response(payload)) as mocked:
            result = IPGeolocationProvider("test-key").collect([("ip", "8.8.8.8")])

        self.assertEqual(result.status, "available")
        self.assertEqual(result.provider, "geolocation")
        self.assertEqual(result.checked, 1)
        observation = result.observations[0]
        self.assertEqual(observation.data["country_code"], "US")
        self.assertEqual(observation.data["latitude"], 37.4056)
        self.assertEqual(observation.data["isp"], "Google LLC")
        self.assertEqual(observation.data["organization"], "Google LLC")
        self.assertEqual(observation.data["asn"], "AS15169")
        self.assertTrue(any(link.relationship == "located_in" for link in result.relationships))
        request = mocked.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.full_url,
            "https://api.ipgeolocation.io/v3/ipgeo?apiKey=test-key&ip=8.8.8.8",
        )

    def test_ip_geolocation_skips_non_public_addresses_without_network_calls(self) -> None:
        with patch("urllib.request.urlopen") as mocked:
            result = IPGeolocationProvider("test-key").collect(
                [
                    ("ip", "10.0.0.1"),
                    ("ip", "127.0.0.1"),
                    ("ip", "169.254.1.1"),
                    ("ip", "224.0.0.1"),
                    ("ip", "192.0.2.10"),
                    ("ip", "not-an-ip"),
                ]
            )
        self.assertEqual(result.status, "available")
        self.assertEqual(result.checked, 0)
        mocked.assert_not_called()

    def test_ip_geolocation_missing_key_does_not_call_network(self) -> None:
        with patch("urllib.request.urlopen") as mocked:
            result = IPGeolocationProvider(None).collect([("ip", "8.8.8.8")])
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.checked, 0)
        self.assertEqual(result.message, "API key not configured")
        mocked.assert_not_called()

    def test_ip_geolocation_http_and_timeout_errors_are_graceful_and_secret_safe(self) -> None:
        secret = "test-secret"
        http_error = urllib.error.HTTPError(
            "https://api.ipgeolocation.io/v3/ipgeo",
            401,
            "Unauthorized",
            {},
            None,
        )
        with patch("urllib.request.urlopen", side_effect=http_error):
            failed = IPGeolocationProvider(secret).collect([("ip", "8.8.8.8")])
        self.assertEqual(failed.status, "error")
        self.assertEqual(failed.checked, 1)
        self.assertNotIn(secret, repr(failed))

        with patch("urllib.request.urlopen", side_effect=TimeoutError):
            timed_out = IPGeolocationProvider(secret).collect([("ip", "8.8.8.8")])
        self.assertEqual(timed_out.status, "error")
        self.assertEqual(timed_out.message, "Provider unavailable or returned invalid data")
        self.assertNotIn(secret, repr(timed_out))

    def test_dns_and_rdap_normalize_results(self) -> None:
        infos = [(None, None, None, None, ("8.8.8.8", 0))]
        def mocked_record(name: str, record_type: str) -> list[object]:
            if name.startswith("_dmarc."):
                return ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com"]
            return {
                "MX": [{"preference": 10, "exchange": "mx.example.com"}],
                "NS": ["ns1.example.com"],
                "TXT": ["v=spf1 -all", "google-site-verification=abc"],
            }[record_type]

        with patch("socket.getaddrinfo", return_value=infos), patch.object(
            DNSProvider, "_resolve_record", side_effect=mocked_record
        ):
            dns = DNSProvider().collect([("domain", "Example.com")])
        self.assertEqual(dns.observations[0].data["addresses"], ["8.8.8.8"])
        self.assertEqual(dns.observations[0].data["mx"][0]["exchange"], "mx.example.com")
        self.assertEqual(dns.observations[0].data["ns"], ["ns1.example.com"])
        self.assertEqual(dns.observations[0].data["txt"], ["v=spf1 -all", "google-site-verification=abc"])
        self.assertEqual(dns.observations[0].data["spf"], ["v=spf1 -all"])
        self.assertEqual(
            dns.observations[0].data["dmarc"],
            [{
                "record": "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com",
                "policy": "reject",
                "subdomain_policy": "quarantine",
                "aggregate_reporting": "mailto:dmarc@example.com",
            }],
        )
        self.assertEqual(dns.relationships[0].relationship, "resolves_to")

        payload = {
            "name": "EXAMPLE.COM",
            "handle": "123",
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "ns1.example.com"}],
            "secureDNS": {"delegationSigned": True},
        }
        with patch("urllib.request.urlopen", return_value=_response(payload)):
            rdap = RDAPProvider().collect([("domain", "example.com")])
        self.assertEqual(rdap.observations[0].data["handle"], "123")
        normalized = rdap.observations[0].data
        self.assertEqual(normalized["registrar"], "Example Registrar")
        self.assertEqual(normalized["nameservers"], ["ns1.example.com"])
        self.assertTrue(normalized["dnssec"]["delegationSigned"])
        self.assertEqual(normalized["registration_date"], "2020-01-01T00:00:00Z")
        self.assertEqual(normalized["expiration_date"], "2030-01-01T00:00:00Z")
        self.assertEqual(normalized["last_updated"], "2025-01-01T00:00:00Z")

    def test_orchestrator_deduplicates_correlates_and_isolates(self) -> None:
        class FakeProvider:
            name = "fake"

            def __init__(self) -> None:
                self.calls = 0

            def lookup(self, entity_type, entity):
                self.calls += 1
                if entity_type == "ip":
                    from app.schemas.threat_intelligence import ThreatObservation

                    return ThreatObservation(
                        provider=self.name,
                        entity_type="ip",
                        entity=entity,
                        kind="test",
                    )
                return None

        class BrokenProvider:
            name = "broken"

            def lookup(self, entity_type, entity):
                raise RuntimeError("must be hidden")

        fake = FakeProvider()
        result = ThreatIntelligenceOrchestrator(providers=[fake, BrokenProvider()]).analyze(
            _email()
        )
        self.assertEqual(len(result.entities), 2)
        self.assertTrue(any(item.relationship == "hosted_by" for item in result.relationships))
        self.assertEqual(result.provider_status[1].status, "error")
        # The same normalized observable is looked up only once per request.
        self.assertEqual(fake.calls, 2)
