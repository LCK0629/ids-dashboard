import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';

export const SESSION_NOTE_MAX_LENGTH: 500;
export const SESSION_PREVIEW_ACTION_POLICY: Readonly<Record<AnalystFeedbackAction, {
  readonly stage5FeedbackType: string;
  readonly category: 'learning' | 'workflow';
  readonly label: string;
  readonly delta: number;
  readonly forceReview: boolean;
  readonly reason: string;
}>>;
export const LEARNING_FEEDBACK_ACTIONS: readonly AnalystFeedbackAction[];
export const WORKFLOW_ACTIONS: readonly AnalystFeedbackAction[];

export interface SessionPreviewCalculation {
  pipelineOperationalPriorityScore: number;
  sessionPreviewPriorityScore: number;
  proposedDelta: number;
  appliedDelta: number;
  reviewRequired: boolean;
  guardrailMessage?: string;
}

export function calculateSessionPreview(
  alert: FeedbackAdjustedAlert,
  action: AnalystFeedbackAction,
): SessionPreviewCalculation;
export function boundSessionNote(value: unknown): string;
export function normalizeSessionNote(value: unknown): string;
