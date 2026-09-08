/**
 * DetectThreatAI Frontend API Client
 * Targets the backend forensic analysis endpoint: POST /api/emails/analyze
 */

import type { EmailAnalysisResponse } from '../types/investigation';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

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
 * @param file .eml email file
 * @returns Full structured EmailAnalysisResponse
 */
export async function analyzeEmail(file: File): Promise<EmailAnalysisResponse> {
  if (!file.name.toLowerCase().endsWith('.eml')) {
    throw new ApiError('Only .eml files are accepted for forensic analysis.', 400);
  }

  const formData = new FormData();
  formData.append('file', file);

  const endpoint = `${API_BASE_URL}/api/emails/analyze`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      let detail = '';
      try {
        const errorJson = await response.json();
        detail = errorJson.detail || JSON.stringify(errorJson);
      } catch {
        detail = await response.text();
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
    const message = err instanceof Error ? err.message : 'Network error connecting to forensic server.';
    throw new ApiError(message, 0);
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
