export const ANALYST_SCHEMA_VERSION: 'ids-dashboard-analyst-v1';
export const ANALYST_ARTIFACT_TYPE: 'analyst_operational_data';
export const DEMO_ARTIFACT_TYPE: 'demonstration_scenarios';
export const EVALUATOR_ARTIFACT_TYPE: 'evaluator_summary';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function findForbiddenGroundTruthPaths(value: unknown, path?: string, matches?: string[]): string[];
export function validateAnalystAlert(alert: unknown, index?: number): ValidationResult;
export function validateStage5DashboardSourceRecord(record: unknown, index?: number): ValidationResult;
export function assertValidStage5DashboardSource<T>(records: T): T;
export function validateAnalystArtifact(
  artifact: unknown,
  options?: { expectedArtifactType?: string }
): ValidationResult;
export function validateEvaluatorArtifact(artifact: unknown): ValidationResult;
export function assertValidAnalystArtifact<T>(
  artifact: T,
  options?: { expectedArtifactType?: string }
): T;
