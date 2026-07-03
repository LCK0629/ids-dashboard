export type AnalystFeedbackAction =
  | 'CONFIRMED_THREAT'
  | 'FALSE_POSITIVE'
  | 'EXPECTED_ACTIVITY'
  | 'NEEDS_INVESTIGATION'
  | 'ESCALATED';

export interface LocalFeedbackOverride {
  alertId: string;
  action: AnalystFeedbackAction;
  scoreDelta: number;
  reviewRequired: boolean;
  reason: string;
  timestamp: string;
  guardrailMessage?: string;
}

export type LocalFeedbackMap = Record<string, LocalFeedbackOverride>;

export type ReplaySpeed = 1 | 2 | 5;

export interface SessionKpis {
  visibleAlerts: number;
  reviewedInSession: number;
  localFeedbackApplied: number;
  averageCurrentRisk: number;
  highRiskAlerts: number;
  requiresReview: number;
  falsePositivesMarked: number;
  escalatedAlerts: number;
  replayProgress: string;
}
