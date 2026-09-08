/**
 * DetectThreatAI Frontend API Client
 * Targets the backend forensic analysis endpoint: POST /api/emails/analyze
 */

import type { EmailAnalysisResponse } from '../types/investigation';

const API_BASE_URL =
  typeof import.meta !== 'undefined' && import.meta.env && typeof import.meta.env.VITE_API_URL === 'string'
    ? import.meta.env.VITE_API_URL
    : '';

/**
 * Standard client timeout for email forensic analysis in milliseconds.
 * Set to 90 seconds to accommodate multi-provider intelligence lookups (DNS/RDAP/AbuseIPDB/VT)
 * and autonomous multi-turn AI tool iterations with bounded rate-limit backoff.
 */
export const ANALYSIS_TIMEOUT_MS = 90_000;

export interface AnalyzeEmailOptions {
  /** Optional custom timeout in milliseconds (defaults to ANALYSIS_TIMEOUT_MS = 90_000). */
  timeoutMs?: number;
  /** Optional external AbortSignal for user or component unmount cancellation. */
  signal?: AbortSignal;
}

export class ApiError extends Error {
  status: number;
  detail?: string;

  constructor(message: string, status: number, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Upload an .eml file to the backend deterministic and AI forensic engine.
 * Implements AbortController-based bounded request timeout and clean cancellation handling.
 *
 * @param file .eml email file
 * @param options Optional timeout override and external AbortSignal
 * @returns Full structured EmailAnalysisResponse
 */
export async function analyzeEmail(
  file: File,
  options?: AnalyzeEmailOptions
): Promise<EmailAnalysisResponse> {
  if (!file.name.toLowerCase().endsWith('.eml')) {
    throw new ApiError('Only .eml files are accepted for forensic analysis.', 400);
  }

  const timeoutMs = options?.timeoutMs ?? ANALYSIS_TIMEOUT_MS;
  const externalSignal = options?.signal;

  // Immediate abort check if parent signal is already aborted
  if (externalSignal?.aborted) {
    throw new ApiError('Investigation request was cancelled.', 0, 'ABORTED');
  }

  const controller = new AbortController();
  let timedOut = false;

  // Propagate external cancellation to internal controller
  let onExternalAbort: (() => void) | undefined;
  if (externalSignal) {
    onExternalAbort = () => {
      controller.abort();
    };
    externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }

  // Setup bounded timeout timer
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs > 0 && timeoutMs < Infinity) {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
  }

  const formData = new FormData();
  formData.append('file', file);

  const endpoint = `${API_BASE_URL}/api/emails/analyze`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      body: formData,
      signal: controller.signal,
    });

    if (!response.ok) {
      let detail = '';
      try {
        const rawText = await response.text();
        try {
          const errorJson = JSON.parse(rawText);
          detail = errorJson.detail || JSON.stringify(errorJson);
        } catch {
          detail = rawText;
        }
      } catch {
        detail = '';
      }

      if (response.status === 413) {
        throw new ApiError('The uploaded email file exceeds the size limit (10MB).', 413, detail);
      }
      if (response.status === 400) {
        throw new ApiError(detail || 'The file could not be parsed as a valid email.', 400, detail);
      }

      throw new ApiError(`Forensic server returned HTTP ${response.status}`, response.status, detail);
    }

    const data: EmailAnalysisResponse = await response.json();
    return data;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }

    const isAbort =
      timedOut ||
      (err instanceof DOMException && err.name === 'AbortError') ||
      (err instanceof Error && err.name === 'AbortError');

    if (isAbort) {
      if (timedOut) {
        throw new ApiError(
          'Investigation request timed out. The backend may still be processing external intelligence. Please retry.',
          408,
          'TIMEOUT'
        );
      }
      if (externalSignal?.aborted) {
        throw new ApiError('Investigation request was cancelled.', 0, 'ABORTED');
      }
      throw new ApiError(
        'Investigation request timed out. The backend may still be processing external intelligence. Please retry.',
        408,
        'TIMEOUT'
      );
    }

    const message = err instanceof Error ? err.message : 'Network error connecting to forensic server.';
    throw new ApiError(message, 0);
  } finally {
    // Guaranteed cleanup of timer and external listener
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    if (externalSignal && onExternalAbort) {
      externalSignal.removeEventListener('abort', onExternalAbort);
    }
  }
}

/**
 * Check health of backend server.
 */
export async function checkBackendHealth(): Promise<{ status: string; healthy: boolean }> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`, { method: 'GET' });
    if (response.ok) {
      const data = await response.json();
      return { status: data.status || 'online', healthy: true };
    }
    return { status: 'degraded', healthy: false };
  } catch {
    return { status: 'offline', healthy: false };
  }
}
