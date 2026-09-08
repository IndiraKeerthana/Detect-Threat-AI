/**
 * DetectThreatAI Centralized Indian Standard Time (Asia/Kolkata, UTC+05:30) Formatter
 * 
 * SIH26106 Mandatory Forensic Presentation Rule:
 * ALL user-facing timestamps presented in the UI MUST display explicitly in Asia/Kolkata (IST).
 * 
 * Strict Forensic Preservation Rule:
 * Raw forensic evidence (original email headers, Message-ID, Received lines) MUST NOT be mutated.
 * Raw values remain intact internally; this formatter governs presentation formatting ONLY.
 */

/**
 * Format any ISO string, RFC 2822 email date, Date object, or numeric epoch timestamp
 * into an explicit Indian Standard Time (IST) presentation string.
 * 
 * Guarantees browser/machine timezone independence by explicitly setting timeZone: "Asia/Kolkata"
 * and locale: "en-IN".
 * 
 * Examples:
 * - 2026-09-08T18:30:00Z -> "09 Sep 2026, 12:00 AM IST"
 * - 2026-09-08T00:00:00Z -> "08 Sep 2026, 05:30 AM IST"
 * - 2026-09-07T11:00:00-04:00 -> "07 Sep 2026, 08:30 PM IST"
 * - Invalid / null / undefined -> "Unavailable"
 */
export function formatISTTimestamp(
  input: string | number | Date | null | undefined,
  fallback = 'Unavailable'
): string {
  if (input === null || input === undefined || input === '') {
    return fallback;
  }

  let ms: number;
  if (typeof input === 'number') {
    ms = input;
  } else if (input instanceof Date) {
    ms = input.getTime();
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed || trimmed === 'null' || trimmed === 'undefined' || trimmed === 'Unavailable') {
      return fallback;
    }
    ms = Date.parse(trimmed);
  } else {
    return fallback;
  }

  if (isNaN(ms) || !Number.isFinite(ms)) {
    return fallback;
  }

  // Reject epoch edge values before 1970 or past 2100
  if (ms < 0 || ms > 4102444800000) {
    return fallback;
  }

  const dateObj = new Date(ms);

  // Explicitly enforce Asia/Kolkata timezone and en-IN locale
  const dtf = new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
  });

  const parts = dtf.formatToParts(dateObj);
  let day = '';
  let month = '';
  let year = '';
  let hour = '';
  let minute = '';
  let dayPeriod = '';

  for (const part of parts) {
    if (part.type === 'day') day = part.value;
    else if (part.type === 'month') month = part.value === 'Sept' ? 'Sep' : part.value;
    else if (part.type === 'year') year = part.value;
    else if (part.type === 'hour') hour = part.value;
    else if (part.type === 'minute') minute = part.value;
    else if (part.type === 'dayPeriod') dayPeriod = part.value.toUpperCase();
  }

  if (!day || !month || !year || !hour || !minute) {
    return fallback;
  }

  return `${day} ${month} ${year}, ${hour}:${minute} ${dayPeriod} IST`;
}

/**
 * Returns the numeric epoch milliseconds for valid timestamp inputs.
 * Used for accurate chronological sorting independent of formatted string representations.
 */
export function getTimestampInstant(input: string | number | Date | null | undefined): number | null {
  if (input === null || input === undefined || input === '') {
    return null;
  }
  let ms: number;
  if (typeof input === 'number') {
    ms = input;
  } else if (input instanceof Date) {
    ms = input.getTime();
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return null;
    ms = Date.parse(trimmed);
  } else {
    return null;
  }

  if (isNaN(ms) || !Number.isFinite(ms) || ms < 0 || ms > 4102444800000) {
    return null;
  }

  return ms;
}

/**
 * Provides dual presentation for forensic reports:
 * Returns both the untouched original forensic header string AND the converted IST presentation.
 */
export function formatRawAndIST(rawInput: string | null | undefined): { raw: string; ist: string } {
  if (!rawInput) {
    return { raw: 'Unavailable', ist: 'Unavailable' };
  }
  const ist = formatISTTimestamp(rawInput, 'Unavailable');
  return {
    raw: rawInput,
    ist,
  };
}
