import { validateAnalystArtifact } from './analystDashboardContract.js';

export class AnalystArtifactLoadError extends Error {
  constructor(code, message, diagnostics = []) {
    super(message);
    this.name = 'AnalystArtifactLoadError';
    this.code = code;
    this.diagnostics = diagnostics;
  }
}

export async function loadValidatedAnalystArtifact(
  artifactUrl,
  { fetchImpl = globalThis.fetch, signal } = {},
) {
  if (typeof artifactUrl !== 'string' || artifactUrl.trim() === '') {
    throw new AnalystArtifactLoadError(
      'invalid_artifact_url',
      'The analyst data asset URL is unavailable.',
    );
  }

  if (typeof fetchImpl !== 'function') {
    throw new AnalystArtifactLoadError(
      'fetch_unavailable',
      'The browser cannot request the analyst data asset.',
    );
  }

  let response;
  try {
    response = await fetchImpl(artifactUrl, {
      cache: 'no-store',
      credentials: 'same-origin',
      signal,
    });
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    throw new AnalystArtifactLoadError(
      'request_failed',
      'The analyst data asset could not be requested.',
    );
  }

  if (!response?.ok) {
    const status = Number.isInteger(response?.status) ? ` (${response.status})` : '';
    throw new AnalystArtifactLoadError(
      'request_failed',
      `The analyst data asset request failed${status}.`,
    );
  }

  let candidate;
  try {
    candidate = await response.json();
  } catch {
    throw new AnalystArtifactLoadError(
      'invalid_json',
      'The analyst data asset is not valid JSON.',
    );
  }

  const validation = validateAnalystArtifact(candidate);
  if (!validation.valid) {
    throw new AnalystArtifactLoadError(
      'validation_failed',
      'The analyst data asset failed validation.',
      validation.errors.slice(0, 8),
    );
  }

  return candidate;
}
