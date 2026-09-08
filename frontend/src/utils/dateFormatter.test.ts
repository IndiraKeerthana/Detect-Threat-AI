import { formatISTTimestamp } from './dateFormatter.ts';
import { normalizeTimelineEvents } from '../services/investigationAdapter.ts';
import type { EmailAnalysisResponse } from '../types/investigation.ts';

function assertStrictEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(message || `Expected ${String(expected)} but got ${String(actual)}`);
  }
}

console.log('--- Running IST Timestamp Formatter Tests ---\n');

assertStrictEqual(
  formatISTTimestamp('2026-09-08T18:30:00Z'),
  '09 Sep 2026, 12:00 AM IST',
  'UTC midnight rollover must be shown in IST'
);
assertStrictEqual(
  formatISTTimestamp('2026-09-08T00:00:00Z'),
  '08 Sep 2026, 05:30 AM IST',
  'UTC timestamp must be shifted to IST'
);
assertStrictEqual(
  formatISTTimestamp('2026-09-07T11:00:00-04:00'),
  '07 Sep 2026, 08:30 PM IST',
  'Offset-aware timestamps must be converted to IST'
);
assertStrictEqual(formatISTTimestamp('not-a-timestamp'), 'Unavailable');
assertStrictEqual(formatISTTimestamp(null), 'Unavailable');
assertStrictEqual(formatISTTimestamp(undefined), 'Unavailable');

// Known UTC instants give the same expected IST output regardless of the host timezone.
assertStrictEqual(formatISTTimestamp(new Date('2026-09-07T11:00:00Z')), '07 Sep 2026, 04:30 PM IST');

const orderedTimeline = normalizeTimelineEvents({
  date: '2026-09-08T12:00:00Z',
  subject: 'Ordering test',
  relay_analysis: {
    relay_hops: [{
      hop_number: 1,
      original_header: 'from mx.example by gateway.example; Tue, 08 Sep 2026 11:58:00 +0000',
      hostnames: ['mx.example'],
      extracted_ips: [],
    }],
    extracted_ips: [],
  },
} as unknown as EmailAnalysisResponse);

assertStrictEqual(orderedTimeline.length, 2);
assertStrictEqual(orderedTimeline[0].timeOffset, 'Tue, 08 Sep 2026 11:58:00 +0000');
assertStrictEqual(orderedTimeline[1].timeOffset, '2026-09-08T12:00:00Z');
assertStrictEqual(formatISTTimestamp(orderedTimeline[0].timeOffset), '08 Sep 2026, 05:28 PM IST');
assertStrictEqual(formatISTTimestamp(orderedTimeline[1].timeOffset), '08 Sep 2026, 05:30 PM IST');

console.log('IST formatter tests passed.');
