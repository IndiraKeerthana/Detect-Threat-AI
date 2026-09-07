import unittest

from app.services.relay_analyzer import analyze_received_headers


class RelayAnalyzerTest(unittest.TestCase):
    def test_reconstructs_order_and_extracts_ipv4_ipv6_and_hosts(self) -> None:
        result = analyze_received_headers(
            [
                "from newest.example (newest.example [198.51.100.22]) by mx.example",
                "from [2001:db8::2] by middle.example via [8.8.8.8]",
                "from origin.example (10.0.0.4) by [203.0.113.7]",
            ]
        )

        self.assertEqual([hop.hop_number for hop in result.relay_hops], [3, 2, 1])
        self.assertEqual(result.relay_hops[0].original_header, "from origin.example (10.0.0.4) by [203.0.113.7]")
        self.assertEqual(result.relay_hops[0].hostnames, ["origin.example"])
        self.assertEqual(
            [item.address for item in result.extracted_ips],
            ["198.51.100.22", "2001:db8::2", "8.8.8.8", "10.0.0.4", "203.0.113.7"],
        )
        self.assertEqual(result.extracted_ips[1].version, 6)
        self.assertEqual(result.extracted_ips[3].classification, "private")
        self.assertEqual(result.extracted_ips[0].classification, "documentation_or_test")
        self.assertEqual(result.probable_source_infrastructure.address, "8.8.8.8")

    def test_multiple_ips_and_reserved_ranges(self) -> None:
        result = analyze_received_headers(
            ["from relay.example [192.168.1.2] (172.16.0.3) by [1.1.1.1]"]
        )

        self.assertEqual(
            [item.address for item in result.relay_hops[0].extracted_ips],
            ["192.168.1.2", "172.16.0.3", "1.1.1.1"],
        )
        self.assertFalse(result.relay_hops[0].extracted_ips[0].is_public_source_candidate)
        self.assertEqual(result.probable_source_infrastructure.address, "1.1.1.1")

    def test_reserved_ip_is_explicitly_classified_and_excluded(self) -> None:
        result = analyze_received_headers(["from relay.example [240.0.0.1] by mx.example"])

        extracted = result.extracted_ips[0]
        self.assertEqual(extracted.classification, "reserved")
        self.assertFalse(extracted.is_public_source_candidate)
        self.assertIsNone(result.probable_source_infrastructure.address)

    def test_malformed_header_is_preserved_without_false_source(self) -> None:
        result = analyze_received_headers(["Received: ???", "from localhost by [127.0.0.1]"])

        self.assertEqual(result.relay_hops[0].original_header, "from localhost by [127.0.0.1]")
        self.assertEqual(result.relay_hops[0].hostnames, ["localhost"])
        self.assertIsNone(result.probable_source_infrastructure.address)
        self.assertEqual(result.probable_source_infrastructure.confidence, "none")

    def test_empty_headers_return_empty_analysis(self) -> None:
        result = analyze_received_headers([])

        self.assertEqual(result.relay_hops, [])
        self.assertEqual(result.extracted_ips, [])
        self.assertIsNone(result.probable_source_infrastructure.address)
