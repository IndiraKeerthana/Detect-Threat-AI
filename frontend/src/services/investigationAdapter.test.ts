/**
 * Forensic Integrity Tests for investigationAdapter.ts
 *
 * Verifies:
 * STEP 8.5-FIX-1: Ensures normalizeGraphData never fabricates ASN, Geolocation, or specimen data.
 * STEP 8.5-FIX-2: Ensures normalizeMapLocation never manufactures fallback coordinates or IPs.
 */

import {
  normalizeGraphData,
  normalizeMapLocation,
  isPrivateOrReservedIP,
  isValidCoordinate,
  normalizeTimelineEvents,
  parseValidTimestamp,
  extractHopTimestamp,
} from './investigationAdapter.ts';
import { caseStore } from './caseStore.ts';
import type { EmailAnalysisResponse } from '../types/investigation.ts';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertStrictEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(message || `Expected ${String(expected)} but got ${String(actual)}`);
  }
}

console.log('--- Running Investigation Adapter Integrity Tests ---\n');

// ============================================================================
// STEP 8.5-FIX-1: GRAPH INTEGRITY TESTS
// ============================================================================

// CASE 1: Backend investigation contains IP but NO ASN or geolocation
console.log('GRAPH CASE 1: IP present, but NO ASN or Geolocation in backend');
const case1Input = {
  message_id: '<test-case-1@example.com>',
  subject: 'Case 1 Subject',
  from: 'sender@example.com',
  to: 'recipient@example.com',
  date: '2026-09-08T12:00:00Z',
  relay_analysis: {
    relay_hops: [
      {
        hop_number: 1,
        original_header: 'from mail.example.com by mx.example.com',
        hostnames: ['mail.example.com'],
        extracted_ips: [{ address: '198.51.100.99', version: 'IPv4' as const, is_private: false }],
      },
    ],
    extracted_ips: [{ address: '198.51.100.99', version: 'IPv4' as const, is_private: false }],
    probable_source_infrastructure: {
      address: '198.51.100.99',
      confidence: 'high',
      reason: 'Last external hop',
    },
    metadata: {
      received_header_count: 1,
      input_header_order: 'top_to_bottom',
      reconstructed_order: 'chronological',
      source_selection_scope: 'external_only',
    },
  },
  security_analysis: {
    summary: 'No threats detected',
    indicators: [],
    authentication_results: {
      headers: [],
      authserv_ids: ['mx.example.com'],
      results: [],
      from_domain: 'example.com',
      alignment_notes: [],
    },
    url_analysis: { urls: [], domains: [] },
    domains: [{ domain: 'example.com', source: 'from' as const }],
    content_signals: { signals: [], normalized_text_length: 50 },
  },
  threat_intelligence: {
    entities: [{ type: 'ip' as const, value: '198.51.100.99', sources: ['relay'] }],
    observations: [
      {
        provider: 'AbuseIPDB',
        entity_type: 'ip' as const,
        entity: '198.51.100.99',
        kind: 'reputation',
        status: 'success' as const,
        data: { abuse_confidence_score: 0 },
        evidence: ['clean reputation'],
        confidence: 'high' as const,
      },
    ],
    relationships: [],
    provider_status: [],
  },
} as unknown as EmailAnalysisResponse;

const case1Result = normalizeGraphData(case1Input);

// Assert IP node exists
const case1IpNode = case1Result.nodes.find((n) => n.id === 'ip:198.51.100.99');
assert(case1IpNode !== undefined, 'Expected IP node ip:198.51.100.99 to exist');
assertStrictEqual(case1IpNode.primaryValue, '198.51.100.99');

// Assert NO ASN59201 node
const case1Asn59201 = case1Result.nodes.find((n) => n.label.includes('ASN59201') || n.id.includes('asn59201'));
assert(!case1Asn59201, 'Violation: Found fabricated ASN59201 node');

// Assert NO TEST-NET-2 node
const case1TestNet = case1Result.nodes.find((n) => n.label.includes('TEST-NET-2') || n.id.includes('test-net'));
assert(!case1TestNet, 'Violation: Found fabricated TEST-NET-2 node');

// Assert NO United States node
const case1USNode = case1Result.nodes.find((n) => n.label.includes('United States') || n.id === 'location:us');
assert(!case1USNode, 'Violation: Found fabricated United States geolocation node');

// Assert NO ASN nodes at all
const case1AnyAsn = case1Result.nodes.filter((n) => n.type === 'asn');
assertStrictEqual(case1AnyAsn.length, 0, `Violation: Expected 0 ASN nodes, found ${case1AnyAsn.length}`);

// Assert NO Geolocation nodes at all
const case1AnyGeo = case1Result.nodes.filter((n) => n.type === 'location');
assertStrictEqual(case1AnyGeo.length, 0, `Violation: Expected 0 Location nodes, found ${case1AnyGeo.length}`);

// Assert NO synthetic ASN edge
const case1AsnEdge = case1Result.edges.find((e) => e.relationship === 'announced_by');
assert(!case1AsnEdge, 'Violation: Found synthetic announced_by edge');

// Assert NO synthetic Geolocation edge
const case1GeoEdge = case1Result.edges.find((e) => e.relationship === 'located_in');
assert(!case1GeoEdge, 'Violation: Found synthetic located_in edge');

console.log('✓ GRAPH CASE 1 Passed: IP exists with 0 fabricated ASN or Geolocation entities/edges.\n');

// CASE 2: Backend investigation contains a verified ASN
console.log('GRAPH CASE 2: Backend investigation contains verified ASN');
const case2Input = {
  ...case1Input,
  threat_intelligence: {
    entities: [{ type: 'ip' as const, value: '198.51.100.99', sources: ['relay'] }],
    observations: [
      {
        provider: 'BGPView',
        entity_type: 'ip' as const,
        entity: '198.51.100.99',
        kind: 'routing',
        status: 'success' as const,
        data: {
          asn: 'AS13335',
          isp: 'Cloudflare, Inc.',
        },
        evidence: ['BGP announcement via AS13335'],
        confidence: 'high' as const,
      },
    ],
    relationships: [],
    provider_status: [],
  },
} as unknown as EmailAnalysisResponse;

const case2Result = normalizeGraphData(case2Input);

const case2AsnNode = case2Result.nodes.find((n) => n.id === 'asn:as13335');
assert(case2AsnNode !== undefined, 'Expected ASN node asn:as13335 to exist');
assertStrictEqual(case2AsnNode.type, 'asn');
assertStrictEqual(case2AsnNode.primaryValue, 'AS13335');
assertStrictEqual(case2AsnNode.label, 'AS13335 (Cloudflare, Inc.)');

const case2AsnEdge = case2Result.edges.find(
  (e) => e.source === 'ip:198.51.100.99' && e.target === 'asn:as13335' && e.relationship === 'announced_by'
);
assert(case2AsnEdge !== undefined, 'Expected announced_by edge from IP to verified ASN node');

const case2AnyGeo = case2Result.nodes.filter((n) => n.type === 'location');
assertStrictEqual(case2AnyGeo.length, 0, 'Expected NO geolocation nodes when none provided');

console.log('✓ GRAPH CASE 2 Passed: Verified ASN created and linked; no geolocation invented.\n');

// CASE 3: Backend investigation contains verified geolocation
console.log('GRAPH CASE 3: Backend investigation contains verified Geolocation');
const case3Input = {
  ...case1Input,
  threat_intelligence: {
    entities: [{ type: 'ip' as const, value: '198.51.100.99', sources: ['relay'] }],
    observations: [
      {
        provider: 'IPInfo',
        entity_type: 'ip' as const,
        entity: '198.51.100.99',
        kind: 'geolocation',
        status: 'success' as const,
        data: {
          country: 'Germany',
          country_code: 'DE',
          city: 'Frankfurt',
          latitude: 50.1109,
          longitude: 8.6821,
        },
        evidence: ['Geolocation verified: Frankfurt, Germany'],
        confidence: 'high' as const,
      },
    ],
    relationships: [],
    provider_status: [],
  },
} as unknown as EmailAnalysisResponse;

const case3Result = normalizeGraphData(case3Input);

const case3GeoNode = case3Result.nodes.find((n) => n.type === 'location');
assert(case3GeoNode !== undefined, 'Expected geolocation node to exist');
assertStrictEqual(case3GeoNode.id, 'location:de');
assertStrictEqual(case3GeoNode.primaryValue, 'Germany');
assertStrictEqual(case3GeoNode.label, 'Frankfurt, Germany [DE]');
assertStrictEqual(case3GeoNode.properties.country, 'Germany');
assertStrictEqual(case3GeoNode.properties.country_code, 'DE');
assertStrictEqual(case3GeoNode.properties.city, 'Frankfurt');
assertStrictEqual(case3GeoNode.properties.latitude, 50.1109);
assertStrictEqual(case3GeoNode.properties.longitude, 8.6821);

const case3GeoEdge = case3Result.edges.find(
  (e) => e.source === 'ip:198.51.100.99' && e.target === 'location:de' && e.relationship === 'located_in'
);
assert(case3GeoEdge !== undefined, 'Expected located_in edge from IP to verified Geolocation node');

const case3AnyAsn = case3Result.nodes.filter((n) => n.type === 'asn');
assertStrictEqual(case3AnyAsn.length, 0, 'Expected NO ASN nodes when none provided');

console.log('✓ GRAPH CASE 3 Passed: Verified Geolocation created with backend properties; no ASN invented.\n');

// CASE 4: Backend investigation contains neither ASN nor geolocation
console.log('GRAPH CASE 4: Backend investigation contains neither ASN nor Geolocation');
const case4Input = {
  subject: 'Case 4 Minimal Test',
  security_analysis: {
    summary: 'Minimal analysis test',
    indicators: [],
    authentication_results: {
      headers: [],
      authserv_ids: [],
      results: [],
      alignment_notes: [],
    },
    url_analysis: { urls: [], domains: [] },
    domains: [],
    content_signals: { signals: [], normalized_text_length: 10 },
  },
} as unknown as EmailAnalysisResponse;

const case4Result = normalizeGraphData(case4Input);

assert(Array.isArray(case4Result.nodes), 'Nodes must be an array');
assert(Array.isArray(case4Result.edges), 'Edges must be an array');
assert(case4Result.nodes.length > 0, 'Root email node should exist');

const case4AsnNodes = case4Result.nodes.filter((n) => n.type === 'asn');
const case4GeoNodes = case4Result.nodes.filter((n) => n.type === 'location');
assertStrictEqual(case4AsnNodes.length, 0, 'Expected 0 ASN nodes');
assertStrictEqual(case4GeoNodes.length, 0, 'Expected 0 Location nodes');

const case4ForbiddenValues = ['ASN59201', 'TEST-NET-2', 'United States', '37.751', '-97.822', 'mail-gw.suspicious-relay.net', 'secure-alerts-update.com'];
for (const val of case4ForbiddenValues) {
  for (const node of case4Result.nodes) {
    assert(!node.label.includes(val), `Violation: Case 4 node has fabricated value "${val}"`);
    assert(!node.primaryValue.includes(val), `Violation: Case 4 node has fabricated value "${val}"`);
  }
}

console.log('✓ GRAPH CASE 4 Passed: Graph remains valid and zero fabricated intelligence appears.\n');

// ============================================================================
// STEP 8.5-FIX-2: MAP GEOLOCATION INTEGRITY TESTS
// ============================================================================

console.log('--- Testing normalizeMapLocation Forensic Integrity ---');

// MAP CASE 1: No probable source infrastructure
console.log('MAP CASE 1: No probable source infrastructure');
const mapCase1Input = {
  relay_analysis: {
    probable_source_infrastructure: {
      address: null,
      confidence: 'none',
      reason: 'No external hops',
    },
  },
  threat_intelligence: {
    observations: [],
  },
} as unknown as EmailAnalysisResponse;

const mapCase1Result = normalizeMapLocation(mapCase1Input);
assertStrictEqual(mapCase1Result, null, 'MAP CASE 1 Failed: Expected null when probable_source_infrastructure is missing/null');
console.log('✓ MAP CASE 1 Passed: Returns null when probable source infrastructure is null.\n');

// MAP CASE 2: Probable source IP exists but there is NO verified geolocation observation
console.log('MAP CASE 2: Probable source IP exists but NO verified geolocation observation');
const mapCase2Input = {
  relay_analysis: {
    probable_source_infrastructure: {
      address: '203.0.113.195',
      confidence: 'high',
      reason: 'Last external relay',
    },
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'AbuseIPDB',
        entity_type: 'ip' as const,
        entity: '203.0.113.195',
        kind: 'reputation',
        status: 'success' as const,
        data: { abuse_confidence_score: 42 },
        evidence: ['Score 42'],
        confidence: 'high' as const,
      },
    ],
  },
} as unknown as EmailAnalysisResponse;

const mapCase2Result = normalizeMapLocation(mapCase2Input);
assertStrictEqual(mapCase2Result, null, 'MAP CASE 2 Failed: Expected null when IP exists but has NO geolocation observation');
console.log('✓ MAP CASE 2 Passed: Returns null when IP exists but lacks verified coordinates.\n');

// MAP CASE 3: Verified geolocation observation exists with Germany coordinates
console.log('MAP CASE 3: Verified geolocation observation exists with Germany coordinates');
const mapCase3Input = {
  relay_analysis: {
    probable_source_infrastructure: {
      address: '198.51.100.99',
      confidence: 'high',
      reason: 'Verified relay host',
    },
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'MaxMind',
        entity_type: 'ip' as const,
        entity: '198.51.100.99',
        kind: 'geolocation',
        status: 'success' as const,
        data: {
          latitude: 50.1109,
          longitude: 8.6821,
          country: 'Germany',
          country_code: 'DE',
          city: 'Frankfurt',
          asn: 'AS13335',
          isp: 'Cloudflare',
          abuse_confidence_score: 12,
        },
        evidence: ['Coordinates verified via MaxMind GeoIP2'],
        confidence: 'high' as const,
      },
    ],
  },
} as unknown as EmailAnalysisResponse;

const mapCase3Result = normalizeMapLocation(mapCase3Input);
assert(mapCase3Result !== null, 'MAP CASE 3 Failed: Expected non-null map location for verified telemetry');
assertStrictEqual(mapCase3Result.ip, '198.51.100.99');
assertStrictEqual(mapCase3Result.latitude, 50.1109);
assertStrictEqual(mapCase3Result.longitude, 8.6821);
assertStrictEqual(mapCase3Result.country, 'Germany');
assertStrictEqual(mapCase3Result.countryCode, 'DE');
assertStrictEqual(mapCase3Result.city, 'Frankfurt');
assertStrictEqual(mapCase3Result.asn, 'AS13335');
assertStrictEqual(mapCase3Result.organization, 'Cloudflare');
assertStrictEqual(mapCase3Result.abuseScore, 12);
console.log('✓ MAP CASE 3 Passed: Returns valid map location matching exact backend values.\n');

// MAP CASE 4: Invalid latitude / longitude
console.log('MAP CASE 4: Invalid latitude / longitude validation');
const invalidCoordinatesList = [
  { lat: 95, lon: 10 }, // Latitude > 90
  { lat: -95, lon: 10 }, // Latitude < -90
  { lat: 10, lon: 185 }, // Longitude > 180
  { lat: 10, lon: -185 }, // Longitude < -180
  { lat: NaN, lon: 10 }, // NaN
  { lat: 10, lon: Infinity }, // Infinity
  { lat: null, lon: 10 }, // Incomplete pair
  { lat: 10, lon: null }, // Incomplete pair
];

for (const { lat, lon } of invalidCoordinatesList) {
  assertStrictEqual(isValidCoordinate(lat, lon), false, `Expected isValidCoordinate(${lat}, ${lon}) to be false`);

  const invalidInput = {
    relay_analysis: {
      probable_source_infrastructure: { address: '203.0.113.50' },
    },
    threat_intelligence: {
      observations: [
        {
          provider: 'BadProvider',
          entity_type: 'ip' as const,
          entity: '203.0.113.50',
          kind: 'geolocation',
          status: 'success' as const,
          data: { latitude: lat, longitude: lon, country: 'Nowhere' },
        },
      ],
    },
  } as unknown as EmailAnalysisResponse;

  const result = normalizeMapLocation(invalidInput);
  assertStrictEqual(result, null, `MAP CASE 4 Failed: Expected null for invalid coords (${lat}, ${lon})`);
}
console.log('✓ MAP CASE 4 Passed: Strict validation rejects NaN, Infinity, out-of-range, and incomplete coordinates.\n');

// MAP CASE 5: Private / documentation IP with no verified geolocation
console.log('MAP CASE 5: Private / documentation IP with no verified geolocation');
const privateIps = [
  '10.0.0.1',
  '172.16.5.10',
  '192.168.1.1',
  '127.0.0.1',
  '169.254.1.1',
  '198.51.100.10', // TEST-NET-2
  '192.0.2.1',     // TEST-NET-1
  '203.0.113.1',   // TEST-NET-3
];

for (const ip of privateIps) {
  assertStrictEqual(isPrivateOrReservedIP(ip), true, `Expected isPrivateOrReservedIP('${ip}') to be true`);

  const privateInput = {
    relay_analysis: {
      probable_source_infrastructure: { address: ip },
    },
    threat_intelligence: {
      observations: [
        {
          provider: 'TestProvider',
          entity_type: 'ip' as const,
          entity: ip,
          kind: 'reputation',
          status: 'success' as const,
          data: { abuse_confidence_score: 0 },
        },
      ],
    },
  } as unknown as EmailAnalysisResponse;

  const res = normalizeMapLocation(privateInput);
  assertStrictEqual(res, null, `MAP CASE 5 Failed: Expected null for private/doc IP ${ip} with no verified geolocation`);
}
console.log('✓ MAP CASE 5 Passed: Private / documentation IPs return null when lacking verified geolocation.\n');

// MAP CASE 6: Verify that specimen values NEVER appear as fallback output
console.log('MAP CASE 6: Verify specimen values NEVER appear as fallback output');
const testInputsForFallbackCheck = [
  // A. Empty object
  {} as EmailAnalysisResponse,
  // B. Null relay analysis
  { relay_analysis: null } as unknown as EmailAnalysisResponse,
  // C. Relay analysis with missing probable_source_infrastructure
  { relay_analysis: { relay_hops: [] } } as unknown as EmailAnalysisResponse,
  // D. Valid Germany observation (Case 3)
  mapCase3Input,
];

const forbiddenStrings = ['198.51.100.10', 'Wichita', 'United States'];
const forbiddenCoords = [
  { lat: 37.751, lon: -97.822 },
];

for (const input of testInputsForFallbackCheck) {
  const result = normalizeMapLocation(input);
  if (result !== null) {
    for (const forbidden of forbiddenStrings) {
      assert(result.ip !== forbidden, `Violation: result.ip contains forbidden fallback "${forbidden}"`);
      assert(result.country !== forbidden, `Violation: result.country contains forbidden fallback "${forbidden}"`);
      assert(result.city !== forbidden, `Violation: result.city contains forbidden fallback "${forbidden}"`);
    }
    for (const { lat, lon } of forbiddenCoords) {
      const isMatch = Math.abs(result.latitude - lat) < 0.0001 && Math.abs(result.longitude - lon) < 0.0001;
      assert(!isMatch, `Violation: result coordinates match forbidden fallback (${lat}, ${lon})`);
    }
  }
}
console.log('✓ MAP CASE 6 Passed: Specimen values (198.51.100.10, 37.751, -97.822, United States, Wichita) NEVER appear as fallbacks.\n');

// ============================================================================
// STEP 8.5-FIX-3: TIMELINE FORENSIC INTEGRITY TESTS
// ============================================================================

console.log('--- Testing normalizeTimelineEvents Forensic Integrity ---');

// TIMELINE CASE 1: Backend contains real email/Received timestamps
console.log('TIMELINE CASE 1: Backend contains real email/Received timestamps');
const timelineCase1Input = {
  message_id: '<msg-1@example.com>',
  subject: 'Case 1 Real Timestamps',
  from: 'sender@example.com',
  to: 'target@example.com',
  date: '2026-09-08T12:00:00Z',
  received: [
    'from mx1.example.com by mail.example.com; 2026-09-08T12:02:00Z',
    'from hop1.example.com by mx1.example.com; 2026-09-08T11:58:00Z',
  ],
  relay_analysis: {
    relay_hops: [
      {
        hop_number: 1,
        original_header: 'from hop1.example.com by mx1.example.com; 2026-09-08T11:58:00Z',
        hostnames: ['hop1.example.com'],
        extracted_ips: [{ address: '203.0.113.50', version: 4, is_private: false }],
      },
      {
        hop_number: 2,
        original_header: 'from mx1.example.com by mail.example.com; 2026-09-08T12:02:00Z',
        hostnames: ['mx1.example.com'],
        extracted_ips: [{ address: '198.51.100.22', version: 4, is_private: false }],
      },
    ],
  },
} as unknown as EmailAnalysisResponse;

const timelineCase1Result = normalizeTimelineEvents(timelineCase1Input);

// Expected: exactly 3 events (Hop 1 @ 11:58:00Z, Ingestion/Email Date @ 12:00:00Z, Hop 2 @ 12:02:00Z)
assertStrictEqual(timelineCase1Result.length, 3, `Expected 3 events, got ${timelineCase1Result.length}`);

// Chronological ordering check
assertStrictEqual(timelineCase1Result[0].timeOffset, '2026-09-08T11:58:00Z', 'Step 1 should be Hop 1 at 11:58:00Z');
assertStrictEqual(timelineCase1Result[0].category, 'RELAY_HOP');
assertStrictEqual(timelineCase1Result[0].step, 1);

assertStrictEqual(timelineCase1Result[1].timeOffset, '2026-09-08T12:00:00Z', 'Step 2 should be Email Date at 12:00:00Z');
assertStrictEqual(timelineCase1Result[1].category, 'INGESTION');
assertStrictEqual(timelineCase1Result[1].step, 2);

assertStrictEqual(timelineCase1Result[2].timeOffset, '2026-09-08T12:02:00Z', 'Step 3 should be Hop 2 at 12:02:00Z');
assertStrictEqual(timelineCase1Result[2].category, 'RELAY_HOP');
assertStrictEqual(timelineCase1Result[2].step, 3);

// Timestamps are unchanged
assertStrictEqual(timelineCase1Result[0].timeOffset, '2026-09-08T11:58:00Z');
assertStrictEqual(timelineCase1Result[1].timeOffset, '2026-09-08T12:00:00Z');
assertStrictEqual(timelineCase1Result[2].timeOffset, '2026-09-08T12:02:00Z');

// Direct extractHopTimestamp assertions
const hop1Time = extractHopTimestamp(timelineCase1Input.relay_analysis!.relay_hops[0]);
assert(hop1Time !== null, 'Expected extractHopTimestamp on Hop 1 to return valid timestamp');
assertStrictEqual(hop1Time.raw, '2026-09-08T11:58:00Z');

console.log('✓ TIMELINE CASE 1 Passed: Real timestamps preserved, ordered chronologically, unchanged.\n');

// TIMELINE CASE 2: Backend contains events/evidence but no timestamps
console.log('TIMELINE CASE 2: Backend contains events/evidence but no timestamps');
const timelineCase2Input = {
  subject: 'Evidence without timestamps',
  date: null,
  received: [],
  relay_analysis: {
    relay_hops: [
      {
        hop_number: 1,
        original_header: 'from mail.example.com by mx.example.com',
        hostnames: ['mail.example.com'],
        extracted_ips: [{ address: '203.0.113.10', version: 4, is_private: false }],
      },
    ],
  },
  security_analysis: {
    authentication_results: {
      authserv_ids: ['mx.example.com'],
      spf: { result: 'fail', raw: 'spf=fail' },
      dkim: { result: 'none', raw: 'dkim=none' },
      dmarc: { result: 'fail', raw: 'dmarc=fail' },
    },
    url_analysis: {
      urls: [{ url: 'http://203.0.113.10/login', domain: '203.0.113.10', scheme: 'http' }],
    },
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'AbuseIPDB',
        entity_type: 'ip',
        entity: '203.0.113.10',
        kind: 'reputation',
        evidence: ['Abuse detected'],
      },
    ],
  },
  correlations: [
    {
      code: 'AUTH_FAIL_URL',
      relationship: 'auth_failure_with_url',
      explanation: 'Authentication failed with suspicious URL',
      evidence: ['spf=fail'],
      entities: ['203.0.113.10'],
    },
  ],
  risk_assessment: {
    score: 85,
    classification: 'phishing',
    rationale: 'High threat',
    factors: [{ code: 'SPF_FAIL', contribution: 30 }],
  },
} as unknown as EmailAnalysisResponse;

const timelineCase2Result = normalizeTimelineEvents(timelineCase2Input);

// Expected: no fabricated timestamps; returns empty array (length === 0)
assertStrictEqual(timelineCase2Result.length, 0, `Expected 0 events for undated evidence, got ${timelineCase2Result.length}`);

// Verify extractHopTimestamp returns null for undated hop
const undatedHopTime = extractHopTimestamp(timelineCase2Input.relay_analysis!.relay_hops[0]);
assertStrictEqual(undatedHopTime, null, 'Expected extractHopTimestamp on undated hop to return null');
console.log('✓ TIMELINE CASE 2 Passed: No fabricated timestamps; undated evidence yields 0 timeline events.\n');

// TIMELINE CASE 3: Backend contains only one real timestamp
console.log('TIMELINE CASE 3: Backend contains only one real timestamp');
const timelineCase3Input = {
  ...timelineCase2Input,
  date: '2026-09-08T14:30:00Z',
} as unknown as EmailAnalysisResponse;

const timelineCase3Result = normalizeTimelineEvents(timelineCase3Input);

// Expected: exactly 1 real timestamped event, no artificial filler events
assertStrictEqual(timelineCase3Result.length, 1, `Expected exactly 1 event, got ${timelineCase3Result.length}`);
assertStrictEqual(timelineCase3Result[0].step, 1);
assertStrictEqual(timelineCase3Result[0].timeOffset, '2026-09-08T14:30:00Z');
assertStrictEqual(timelineCase3Result[0].category, 'INGESTION');
console.log('✓ TIMELINE CASE 3 Passed: Exactly one real timestamped event; no filler events created.\n');

// TIMELINE CASE 4: Regression check for specimen values
console.log('TIMELINE CASE 4: Regression check for specimen values');
const forbiddenTimeOffsets = [
  'T+00:00',
  'T+00:15',
  'T+00:30',
  'T+00:45',
  'T+01:00',
];

const testInputsForTimelineRegression = [
  {} as EmailAnalysisResponse,
  timelineCase1Input,
  timelineCase2Input,
  timelineCase3Input,
];

for (const input of testInputsForTimelineRegression) {
  const events = normalizeTimelineEvents(input);
  for (const evt of events) {
    for (const forbidden of forbiddenTimeOffsets) {
      assert(evt.timeOffset !== forbidden, `Violation: Found forbidden timeOffset "${forbidden}" in event ${evt.id}`);
    }
    assert(!/^T[+-]/i.test(evt.timeOffset), `Violation: Found synthetic relative offset pattern in event ${evt.id}: "${evt.timeOffset}"`);
    assert(!evt.description.includes('198.51.100.10'), `Violation: Event description contains specimen IP 198.51.100.10`);
    assert(!evt.relatedEntityId?.includes('secure-alerts-update.com'), `Violation: Event relatedEntityId contains specimen domain secure-alerts-update.com`);
  }
}
console.log('✓ TIMELINE CASE 4 Passed: Specimen offsets (T+00:00, T+00:15, T+00:30, T+00:45, T+01:00) NEVER appear.\n');

// TIMELINE CASE 5: Invalid/null/malformed timestamps
console.log('TIMELINE CASE 5: Invalid/null/malformed timestamps');
const malformedInput = {
  date: 'not-a-date',
  received: ['from bad.server; invalid-rfc-date'],
  relay_analysis: {
    relay_hops: [
      {
        hop_number: 1,
        original_header: 'from bad.server; not-a-valid-timestamp',
        hostnames: ['bad.server'],
        extracted_ips: [{ address: '203.0.113.1', version: 4, is_private: false }],
        timestamp: 'null',
      },
      {
        hop_number: 2,
        original_header: 'from bad2.server; 99999-99-99',
        hostnames: ['bad2.server'],
        extracted_ips: [{ address: '203.0.113.2', version: 4, is_private: false }],
        timestamp: 'undefined',
      },
    ],
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'TestProvider',
        entity_type: 'ip',
        entity: '203.0.113.1',
        kind: 'reputation',
        retrieved_at: 'T+00:35',
        evidence: [],
      },
      {
        provider: 'TestProvider2',
        entity_type: 'ip',
        entity: '203.0.113.2',
        kind: 'reputation',
        retrieved_at: '',
        evidence: [],
      },
    ],
  },
  ai_investigation: {
    tool_calls: [
      {
        name: 'dns_lookup',
        arguments: {},
        result_summary: 'lookup',
        status: 'success',
        timestamp: 'T+00:48',
      },
    ],
  },
} as unknown as EmailAnalysisResponse;

const malformedResult = normalizeTimelineEvents(malformedInput);
assertStrictEqual(malformedResult.length, 0, `Expected 0 events for malformed timestamps, got ${malformedResult.length}`);

// Test parseValidTimestamp directly with various invalid inputs
assertStrictEqual(parseValidTimestamp('not-a-date'), null);
assertStrictEqual(parseValidTimestamp('null'), null);
assertStrictEqual(parseValidTimestamp('undefined'), null);
assertStrictEqual(parseValidTimestamp(''), null);
assertStrictEqual(parseValidTimestamp('   '), null);
assertStrictEqual(parseValidTimestamp(null), null);
assertStrictEqual(parseValidTimestamp(undefined), null);
assertStrictEqual(parseValidTimestamp('T+00:00'), null);
assertStrictEqual(parseValidTimestamp('T+00:15'), null);
assertStrictEqual(parseValidTimestamp('T+00:30'), null);
assertStrictEqual(parseValidTimestamp('T+00:45'), null);
assertStrictEqual(parseValidTimestamp('T+01:00'), null);
assertStrictEqual(parseValidTimestamp('T+0s'), null);
assertStrictEqual(parseValidTimestamp(NaN), null);
assertStrictEqual(parseValidTimestamp(Infinity), null);
assertStrictEqual(parseValidTimestamp(-100), null);
assertStrictEqual(parseValidTimestamp(5000000000000), null);

console.log('✓ TIMELINE CASE 5 Passed: Invalid/null/malformed timestamps strictly rejected; no fallback timestamps created.\n');

// ============================================================================
// STEP 8.5-FIX-4: SPECIMEN FALLBACK INTEGRITY TESTS
// ============================================================================

console.log('--- Running STEP 8.5-FIX-4 Specimen Fallback Integrity Tests ---\n');

const SPECIMEN_FORBIDDEN = [
  '198.51.100.10',
  'secure-alerts-update.com',
  'NameCheap',
  'ASN59201',
  'Wichita',
  'TEST-NET-2',
  'mail-gw.suspicious-relay.net',
  'suspicious-relay',
];

// FIX-4 CASE 1: Backend has no source IP/domain/registrar/ASN/geo
console.log('FIX-4 CASE 1: Backend has no source IP/domain/registrar/ASN/geo');
const emptyBackendInput = {
  message_id: '<empty-test@local.internal>',
  date: '2026-09-08T10:00:00Z',
  subject: 'Empty Telemetry Test',
  from: 'user@example.com',
  to: 'recipient@example.com',
  relay_analysis: {
    relay_hops: [],
    extracted_ips: [],
    probable_source_infrastructure: {
      address: null,
      confidence: 'none',
      reason: 'No external relay detected',
    },
  },
  threat_intelligence: {
    entities: [],
    observations: [],
    relationships: [],
    provider_status: [],
  },
  security_analysis: {
    authentication_results: {
      headers: [],
      authserv_ids: [],
      results: [],
      spf: null,
      dkim: null,
      dmarc: null,
      from_domain: null,
      alignment_notes: [],
    },
    indicators: [],
  },
} as unknown as EmailAnalysisResponse;

const emptyMap = normalizeMapLocation(emptyBackendInput);
assertStrictEqual(emptyMap, null, 'Expected null map location for empty backend data');

const emptyGraph = normalizeGraphData(emptyBackendInput);
for (const node of emptyGraph.nodes) {
  for (const forbidden of SPECIMEN_FORBIDDEN) {
    assert(!node.label?.includes(forbidden), `Forbidden specimen "${forbidden}" found in graph node label "${node.label}"`);
    assert(!node.primaryValue?.includes(forbidden), `Forbidden specimen "${forbidden}" found in graph node value "${node.primaryValue}"`);
  }
}
for (const edge of emptyGraph.edges) {
  for (const forbidden of SPECIMEN_FORBIDDEN) {
    assert(!edge.id.includes(forbidden), `Forbidden specimen "${forbidden}" found in graph edge id "${edge.id}"`);
  }
}

const emptyCase = caseStore.createCaseFromAnalysis(emptyBackendInput);
assertStrictEqual(emptyCase.sourceIp, 'Unavailable', `Expected sourceIp 'Unavailable', got ${emptyCase.sourceIp}`);
assertStrictEqual(emptyCase.riskScore, 0, `Expected riskScore 0, got ${emptyCase.riskScore}`);
assertStrictEqual(emptyCase.classification, 'unclassified', `Expected classification 'unclassified', got ${emptyCase.classification}`);
for (const forbidden of SPECIMEN_FORBIDDEN) {
  assert(!emptyCase.sourceIp?.includes(forbidden), `Case sourceIp must not contain ${forbidden}`);
  assert(!emptyCase.sender?.includes(forbidden), `Case sender must not contain ${forbidden}`);
}
console.log('✓ FIX-4 CASE 1 Passed: No specimen values appear in normalized output when backend has no IP/domain/registrar/ASN/geo.\n');

// FIX-4 CASE 2: Backend provides real infrastructure data
console.log('FIX-4 CASE 2: Backend provides real infrastructure data');
const realBackendInput = {
  message_id: '<real-data@corp.org>',
  date: '2026-09-08T11:00:00Z',
  from: 'alerts@legitimate-security.org',
  relay_analysis: {
    relay_hops: [
      {
        hop_number: 1,
        extracted_ips: [{ address: '198.51.100.77', version: 4, is_public_source_candidate: true, hop_number: 1 }],
        hostnames: ['mx-out.legitimate-security.org'],
      },
    ],
    extracted_ips: [{ address: '198.51.100.77', version: 4, is_public_source_candidate: true, hop_number: 1 }],
    probable_source_infrastructure: {
      address: '198.51.100.77',
      confidence: 'high',
      reason: 'Verified border gateway',
    },
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'AbuseIPDB',
        entity_type: 'ip',
        entity: '198.51.100.77',
        kind: 'reputation',
        status: 'success',
        data: {
          latitude: 48.8566,
          longitude: 2.3522,
          country: 'France',
          country_code: 'FR',
          city: 'Paris',
          asn: 'AS12345',
          isp: 'Real Telecom SA',
          abuse_confidence_score: 12,
          geo_verified: true,
        },
        confidence: 'high',
      },
    ],
  },
  risk_assessment: {
    score: 35,
    level: 'low',
    classification: 'benign',
  },
} as unknown as EmailAnalysisResponse;

const realMap = normalizeMapLocation(realBackendInput);
assert(realMap !== null, 'Expected real map location');
assertStrictEqual(realMap.ip, '198.51.100.77');
assertStrictEqual(realMap.latitude, 48.8566);
assertStrictEqual(realMap.longitude, 2.3522);
assertStrictEqual(realMap.country, 'France');
assertStrictEqual(realMap.city, 'Paris');
assertStrictEqual(realMap.asn, 'AS12345');
assertStrictEqual(realMap.organization, 'Real Telecom SA');
assertStrictEqual(realMap.abuseScore, 12);

const realCase = caseStore.createCaseFromAnalysis(realBackendInput);
assertStrictEqual(realCase.sourceIp, '198.51.100.77');
assertStrictEqual(realCase.riskScore, 35);
assertStrictEqual(realCase.classification, 'benign');
console.log('✓ FIX-4 CASE 2 Passed: Exact backend values are displayed.\n');

// FIX-4 CASE 3: Backend provides partial data
console.log('FIX-4 CASE 3: Backend provides partial data');
const partialBackendInput = {
  message_id: '<partial@corp.org>',
  date: '2026-09-08T12:00:00Z',
  from: 'info@partial-domain.com',
  relay_analysis: {
    probable_source_infrastructure: {
      address: '198.51.100.88',
      confidence: 'medium',
      reason: 'Public relay hop',
    },
  },
  threat_intelligence: {
    observations: [
      {
        provider: 'MaxMind',
        entity_type: 'ip',
        entity: '198.51.100.88',
        kind: 'geolocation',
        status: 'success',
        data: {
          latitude: 51.5074,
          longitude: -0.1278,
          country: 'United Kingdom',
          geo_verified: true,
          // No ASN, no city, no organization, no abuse score
        },
        confidence: 'medium',
      },
    ],
  },
} as unknown as EmailAnalysisResponse;

const partialMap = normalizeMapLocation(partialBackendInput);
assert(partialMap !== null, 'Expected partial map location');
assertStrictEqual(partialMap.country, 'United Kingdom');
assertStrictEqual(partialMap.city, undefined, 'Missing city must remain undefined');
assertStrictEqual(partialMap.asn, undefined, 'Missing ASN must remain undefined');
assertStrictEqual(partialMap.organization, undefined, 'Missing organization must remain undefined');
assertStrictEqual(partialMap.abuseScore, undefined, 'Missing abuseScore must remain undefined');
console.log('✓ FIX-4 CASE 3 Passed: Available fields display; missing fields remain undefined/unavailable without synthetic values.\n');

// FIX-4 CASE 4: Production normalization/report path receives empty intelligence
console.log('FIX-4 CASE 4: Production normalization/report path receives empty intelligence');
const emptyIntelInput = {
  message_id: '<no-intel@example.com>',
  relay_analysis: null,
  threat_intelligence: null,
  security_analysis: null,
  risk_assessment: null,
} as unknown as EmailAnalysisResponse;

const emptyIntelMap = normalizeMapLocation(emptyIntelInput);
assertStrictEqual(emptyIntelMap, null, 'normalizeMapLocation returns null for empty intelligence');

const emptyIntelGraph = normalizeGraphData(emptyIntelInput);
for (const node of emptyIntelGraph.nodes) {
  assert(node.type !== 'asn', 'No ASN node manufactured on empty intelligence');
  assert(node.type !== 'location', 'No location node manufactured on empty intelligence');
  for (const forbidden of SPECIMEN_FORBIDDEN) {
    assert(!node.label?.includes(forbidden), `Node ${node.id} contains forbidden specimen ${forbidden}`);
  }
}

const emptyIntelCase = caseStore.createCaseFromAnalysis(emptyIntelInput);
assertStrictEqual(emptyIntelCase.sourceIp, 'Unavailable');
assertStrictEqual(emptyIntelCase.riskScore, 0);
assertStrictEqual(emptyIntelCase.classification, 'unclassified');
console.log('✓ FIX-4 CASE 4 Passed: No fake IP/domain/registrar/ASN/location/reputation produced on empty intelligence.\n');

// FIX-4 CASE 5: Specimen regression across multiple arbitrary inputs
console.log('FIX-4 CASE 5: Specimen regression verification');
const regressionInputs = [
  {} as EmailAnalysisResponse,
  { from: 'test@domain.org' } as EmailAnalysisResponse,
  emptyBackendInput,
  partialBackendInput,
  emptyIntelInput,
];

for (const input of regressionInputs) {
  const mapResult = normalizeMapLocation(input);
  if (mapResult) {
    assert(mapResult.ip !== '198.51.100.10', 'Forbidden: 198.51.100.10 in map');
    assert(mapResult.asn !== 'ASN59201', 'Forbidden: ASN59201 in map');
    assert(mapResult.organization !== 'TEST-NET-2', 'Forbidden: TEST-NET-2 in map');
    assert(mapResult.city !== 'Wichita', 'Forbidden: Wichita in map');
  }

  const graphResult = normalizeGraphData(input);
  for (const n of graphResult.nodes) {
    for (const forbidden of SPECIMEN_FORBIDDEN) {
      assert(!n.label?.includes(forbidden), `Forbidden ${forbidden} in node ${n.id}`);
      assert(!n.primaryValue?.includes(forbidden), `Forbidden ${forbidden} in node ${n.id} value`);
    }
  }

  const caseResult = caseStore.createCaseFromAnalysis(input);
  assert(caseResult.sourceIp !== '198.51.100.10', 'Forbidden: 198.51.100.10 in case sourceIp');
  assert(caseResult.riskScore !== 85 && caseResult.riskScore !== 92, 'Forbidden: fake riskScore in case');
  for (const forbidden of SPECIMEN_FORBIDDEN) {
    assert(!caseResult.sourceIp?.includes(forbidden), `Forbidden ${forbidden} in case sourceIp`);
  }
}
console.log('✓ FIX-4 CASE 5 Passed: Specimen values (198.51.100.10, secure-alerts-update.com, NameCheap, ASN59201, Wichita, TEST-NET-2, suspicious-relay) NEVER appear as production fallbacks.\n');

console.log('================================================================');
console.log('ALL FORENSIC INTEGRITY TESTS (GRAPH + MAP + TIMELINE + FALLBACKS) PASSED!');
console.log('================================================================');

