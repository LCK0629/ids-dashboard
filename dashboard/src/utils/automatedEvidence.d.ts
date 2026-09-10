import type { AnalystAlertV1, MlExplanation, ShapFeatureContribution } from '../types/dashboardData';

export const ML_CONFIDENCE_HELPER_TEXT: string;
export const PREDICTION_MARGIN_HELPER_TEXT: string;
export const SHAP_HELPER_TEXT: string;
export const SHAP_NON_CAUSAL_TEXT: string;

export interface EvidenceStatePresentation {
  key: string;
  label: string;
  explanation: string;
  tone?: string;
}

export interface ShapFeatureWithWidth extends ShapFeatureContribution {
  visualWidth: number;
}

export function getDetectorStatePresentation(alert: AnalystAlertV1): EvidenceStatePresentation;
export function getMlAvailabilityPresentation(ml: AnalystAlertV1['mlEvidence']): EvidenceStatePresentation;
export function formatEvidenceReason(reason?: string | null): string;
export function formatModelConfidence(value?: number | null): string;
export function formatPredictionMargin(value?: number | null): string;
export function formatFeatureValue(value: unknown): string;
export function formatSignedShap(value: number): string;
export function normalizeShapWidths(features: ShapFeatureContribution[]): ShapFeatureWithWidth[];
export function normalizeShapGroups(
  supporting: ShapFeatureContribution[],
  opposing: ShapFeatureContribution[]
): { supporting: ShapFeatureWithWidth[]; opposing: ShapFeatureWithWidth[] };
export function shapDirectionLabel(direction: ShapFeatureContribution['direction'], predictedClass?: string | null): string;
export function getTreeShapPresentation(ml: AnalystAlertV1['mlEvidence']): {
  available: boolean;
  title: string;
  detail: string;
};
export function shortenHash(value?: string | null, leading?: number, trailing?: number): string;
