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
  visibleRecords: number;
  allDetectionRecords: number;
  activeAlerts: number;
  suppressedResolved: number;
  reviewedInSession: number;
  localFeedbackApplied: number;
  averageCurrentRisk: number;
  highRiskRecords: number;
  requiresReview: number;
  falsePositivesMarked: number;
  expectedActivityMarked: number;
  confirmedThreats: number;
  escalatedAlerts: number;
  needsInvestigation: number;
  averageRiskBeforeLocalFeedback: number;
  averageRiskAfterLocalFeedback: number;
  averageRiskChange: number;
  reviewRequiredBeforeLocalFeedback: number;
  reviewRequiredAfterLocalFeedback: number;
  guardrailsTriggered: number;
  replayProgress: string;
}
