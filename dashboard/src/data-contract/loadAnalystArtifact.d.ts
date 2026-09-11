import type { AnalystArtifactV1 } from '../types/dashboardData';

export class AnalystArtifactLoadError extends Error {
  code: string;
  diagnostics: string[];
  constructor(code: string, message: string, diagnostics?: string[]);
}

interface AnalystArtifactLoadOptions {
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
}

export function loadValidatedAnalystArtifact(
  artifactUrl: string,
  options?: AnalystArtifactLoadOptions,
): Promise<AnalystArtifactV1>;
