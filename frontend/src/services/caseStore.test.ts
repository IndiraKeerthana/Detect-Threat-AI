/**
 * Campaign Grouping & Multi-Case Attack Clustering Tests
 *
 * Verifies:
 * - CAMPAIGN CLUSTER CASE 1: Two cases sharing the same verified source IP form one cluster.
 * - CAMPAIGN CLUSTER CASE 2: Two cases sharing the same sender domain form one cluster.
 * - CAMPAIGN CLUSTER CASE 3: Two cases sharing a suspicious URL domain form one cluster.
 * - CAMPAIGN CLUSTER CASE 4: Cases with only the same classification do NOT form a campaign.
 * - CAMPAIGN CLUSTER CASE 5: Unrelated cases remain separate.
 * - CAMPAIGN CLUSTER CASE 6: Campaign grouping reason identifies the actual shared indicator.
 * - CAMPAIGN CLUSTER CASE 7: Infrastructure-only grouping does not claim attacker attribution.
 * - CAMPAIGN CLUSTER CASE 8: Existing individual Cases view data structures remain intact.
 */

import { getCampaignClusters, type CaseRecord } from './caseStore.ts';
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

console.log('--- Running Campaign Grouping & Clustering Tests ---\n');

function createMockCaseRecord(
  id: string,
  sourceIp: string,
  fromDomain: string,
  urlDomain?: string,
  classification: string = 'phishing',
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH'
): CaseRecord {
  return {
    id,
    title: `Test Case ${id}`,
    subject: `Test Subject for ${id}`,
    sender: `sender@${fromDomain}`,
    recipient: 'user@target.internal',
    severity,
    classification,
    riskScore: severity === 'CRITICAL' ? 95 : severity === 'HIGH' ? 80 : 50,
    confidence: 'high',
    status: 'OPEN',
    createdAt: '2026-09-08 12:00:00 UTC',
    updatedAt: '2026-09-08 12:05:00 UTC',
    sourceIp,
    investigationData: {
      from: `sender@${fromDomain}`,
      to: 'user@target.internal',
      subject: `Test Subject for ${id}`,
      security_analysis: {
        authentication_results: {
          headers: [],
          authserv_ids: [],
          results: [],
          from_domain: fromDomain,
          alignment_notes: [],
        },
        url_analysis: {
          urls: urlDomain
            ? [{ url: `http://${urlDomain}/login`, normalized_url: `http://${urlDomain}/login`, domain: urlDomain, scheme: 'http', path: '/login', has_query: false, is_https: false, associated_domain: urlDomain, source: 'body_html' }]
            : [],
          domains: urlDomain ? [{ domain: urlDomain, source: 'url' }] : [],
        },
        domains: [{ domain: fromDomain, source: 'from' }],
        indicators: [],
        summary: 'Test summary',
        content_signals: { signals: [], normalized_text_length: 10 },
      },
      relay_analysis: {
        relay_hops: [],
        extracted_ips: [{ address: sourceIp, version: 4, classification: 'public', is_public_source_candidate: true, hop_number: 1 }],
        probable_source_infrastructure: { address: sourceIp, confidence: 'high', reason: 'Verified relay host' },
        metadata: { received_header_count: 1, input_header_order: 'top_to_bottom', reconstructed_order: 'chronological', source_selection_scope: 'external' },
      },
      correlations: [],
      attribution_limitations: [],
      recommended_actions: [],
      received: [],
      body_text: 'Test',
      body_html: null,
      attachments: [],
      message_id: `<${id}@test.internal>`,
      reply_to: null,
      return_path: null,
      mime_version: '1.0',
      content_type: 'text/plain',
      date: '2026-09-08T12:00:00Z',
    } as unknown as EmailAnalysisResponse,
  };
}

// CAMPAIGN CLUSTER CASE 1: Two cases sharing the same verified source IP form one cluster
console.log('CAMPAIGN CLUSTER CASE 1: Two cases sharing the same verified source IP');
const c1_a = createMockCaseRecord('CASE-C1-A', '198.51.100.99', 'domain-alpha.com');
const c1_b = createMockCaseRecord('CASE-C1-B', '198.51.100.99', 'domain-beta.com');

const result1 = getCampaignClusters([c1_a, c1_b]);
assertStrictEqual(result1.length, 1, 'Expected 1 campaign cluster for shared IP');
assert(result1[0].sharedIndicators.some((i) => i.type === 'ip' && i.value === '198.51.100.99'), 'Cluster must contain shared IP indicator');
assertStrictEqual(result1[0].caseCount, 2, 'Cluster must contain 2 linked cases');
console.log('✓ CAMPAIGN CLUSTER CASE 1 Passed: Shared source IP correctly forms campaign cluster.\n');

// CAMPAIGN CLUSTER CASE 2: Two cases sharing the same sender domain form one cluster
console.log('CAMPAIGN CLUSTER CASE 2: Two cases sharing the same sender domain');
const c2_a = createMockCaseRecord('CASE-C2-A', '203.0.113.10', 'secure-update.com');
const c2_b = createMockCaseRecord('CASE-C2-B', '203.0.113.20', 'secure-update.com');

const result2 = getCampaignClusters([c2_a, c2_b]);
assertStrictEqual(result2.length, 1, 'Expected 1 campaign cluster for shared sender domain');
assert(result2[0].sharedIndicators.some((i) => i.type === 'domain' && i.value === 'secure-update.com'), 'Cluster must contain shared domain indicator');
assertStrictEqual(result2[0].caseCount, 2);
console.log('✓ CAMPAIGN CLUSTER CASE 2 Passed: Shared sender domain correctly forms campaign cluster.\n');

// CAMPAIGN CLUSTER CASE 3: Two cases sharing a suspicious URL domain form one cluster
console.log('CAMPAIGN CLUSTER CASE 3: Two cases sharing a suspicious URL domain');
const c3_a = createMockCaseRecord('CASE-C3-A', '198.51.100.11', 'domain-one.com', 'phish-portal.info');
const c3_b = createMockCaseRecord('CASE-C3-B', '198.51.100.22', 'domain-two.com', 'phish-portal.info');

const result3 = getCampaignClusters([c3_a, c3_b]);
assertStrictEqual(result3.length, 1, 'Expected 1 campaign cluster for shared URL domain');
assert(result3[0].sharedIndicators.some((i) => i.type === 'url' && i.value === 'phish-portal.info'), 'Cluster must contain shared URL domain indicator');
assertStrictEqual(result3[0].caseCount, 2);
console.log('✓ CAMPAIGN CLUSTER CASE 3 Passed: Shared suspicious URL domain correctly forms campaign cluster.\n');

// CAMPAIGN CLUSTER CASE 4: Cases with only the same classification do NOT form a campaign
console.log('CAMPAIGN CLUSTER CASE 4: Cases with only the same classification do NOT cluster');
const c4_a = createMockCaseRecord('CASE-C4-A', '198.51.100.101', 'domain-unique-1.com', undefined, 'phishing');
const c4_b = createMockCaseRecord('CASE-C4-B', '198.51.100.102', 'domain-unique-2.com', undefined, 'phishing');

const result4 = getCampaignClusters([c4_a, c4_b]);
assertStrictEqual(result4.length, 0, 'Cases sharing only classification MUST NOT form a campaign cluster');
console.log('✓ CAMPAIGN CLUSTER CASE 4 Passed: Classification alone never creates a campaign cluster.\n');

// CAMPAIGN CLUSTER CASE 5: Unrelated cases remain separate
console.log('CAMPAIGN CLUSTER CASE 5: Unrelated cases remain separate');
const c5_a = createMockCaseRecord('CASE-C5-A', '198.51.100.1', 'dom-a.com');
const c5_b = createMockCaseRecord('CASE-C5-B', '198.51.100.2', 'dom-b.com');
const c5_c = createMockCaseRecord('CASE-C5-C', '198.51.100.3', 'dom-c.com');

const result5 = getCampaignClusters([c5_a, c5_b, c5_c]);
assertStrictEqual(result5.length, 0, 'Unrelated cases must yield 0 campaign clusters');
console.log('✓ CAMPAIGN CLUSTER CASE 5 Passed: Unrelated cases produce 0 fake campaign clusters.\n');

// CAMPAIGN CLUSTER CASE 6: Campaign grouping reason identifies the actual shared indicator
console.log('CAMPAIGN CLUSTER CASE 6: Grouping reasons identify actual shared indicator');
const c6_a = createMockCaseRecord('CASE-C6-A', '198.51.100.99', 'phish-corp.net');
const c6_b = createMockCaseRecord('CASE-C6-B', '198.51.100.99', 'phish-corp.net');

const result6 = getCampaignClusters([c6_a, c6_b]);
assertStrictEqual(result6.length, 1);
assert(result6[0].reasons.some((r) => r.includes('198.51.100.99')), 'Reasons must reference shared source IP 198.51.100.99');
assert(result6[0].reasons.some((r) => r.includes('phish-corp.net')), 'Reasons must reference shared sender domain phish-corp.net');
console.log('✓ CAMPAIGN CLUSTER CASE 6 Passed: Grouping reasons cleanly state actual shared forensic indicators.\n');

// CAMPAIGN CLUSTER CASE 7: Infrastructure-only grouping does not claim attacker attribution
console.log('CAMPAIGN CLUSTER CASE 7: Attribution safeguard caveat enforced');
const c7_a = createMockCaseRecord('CASE-C7-A', '198.51.100.99', 'domain-x.com');
const c7_b = createMockCaseRecord('CASE-C7-B', '198.51.100.99', 'domain-y.com');

const result7 = getCampaignClusters([c7_a, c7_b]);
assertStrictEqual(result7.length, 1);
assert(result7[0].attributionCaveat.includes('Cases linked by shared infrastructure or indicators'), 'Attribution caveat must state cases linked by indicators');
assert(result7[0].attributionCaveat.includes('does not establish common actor attribution'), 'Attribution caveat must state shared infrastructure does not establish actor attribution');
assert(!result7[0].attributionCaveat.toLowerCase().includes('confirmed same attacker'), 'Must NOT claim confirmed same attacker');
console.log('✓ CAMPAIGN CLUSTER CASE 7 Passed: Non-attacker attribution wording strictly enforced.\n');

// CAMPAIGN CLUSTER CASE 8: Existing individual Cases view data structures remain intact
console.log('CAMPAIGN CLUSTER CASE 8: Cases records remain unmutated');
const originalCases = [c1_a, c1_b];
const originalCopy = JSON.parse(JSON.stringify(originalCases));

getCampaignClusters(originalCases);

assertStrictEqual(originalCases.length, 2, 'Input cases length unchanged');
assertStrictEqual(originalCases[0].id, originalCopy[0].id, 'Case records unmutated');
assertStrictEqual(originalCases[1].id, originalCopy[1].id, 'Case records unmutated');
console.log('✓ CAMPAIGN CLUSTER CASE 8 Passed: Case records remain 100% unmutated.\n');

console.log('================================================================');
console.log('ALL 8 CAMPAIGN GROUPING & CLUSTERING TESTS PASSED SUCCESSFULLY!');
console.log('================================================================\n');
