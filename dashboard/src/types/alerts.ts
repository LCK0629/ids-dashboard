export type FilterKey =
  | 'all'
  | 'requires-review'
  | 'feedback-applied'
  | 'high-risk'
  | 'infiltration'
  | 'signature-ml-disagree'
  | 'guardrail-applied'
  | 'benign'
  | 'malicious';

export interface FeedbackAdjustedAlert {
  id: string;
  fusionRiskScore?: number;
  currentRiskScore?: number;
  feedbackApplied?: boolean;
  feedbackAdjustment?: number;
  requiresAnalystReview?: boolean;
  requiresAnalystReviewBeforeFeedback?: boolean;
  fusionAttackType?: string;
  fusionDecision?: string;
  fusionEvidence?: string;
  fusionConfidenceLevel?: string;
  signatureHit?: boolean;
  signatureId?: string | null;
  signatureAttackType?: string | null;
  signatureSeverity?: string | null;
  signatureEvidence?: string;
  mlPredictedAttackType?: string | null;
  modelConfidence?: number | null;
  baseRiskScore?: number;
  matchedFeedbackId?: string | null;
  matchedExceptionId?: string | null;
  matchedExceptionType?: string | null;
  feedbackReason?: string;
  feedbackGuardrailsApplied?: string[];
  analystFeedbackStatus?: string;
  groundTruth?: string;
  trueAttackType?: string;
  mappedAttackType?: string;
  rawLabel?: string;
}

export interface FeedbackEvaluationSummary {
  totalAlerts?: number;
  alertsAdjusted?: number;
  reviewQueueBefore?: number;
  reviewQueueAfter?: number;
  averageRiskBeforeFeedback?: number;
  averageRiskAfterFeedback?: number;
  scoreAdjustmentGuardrailCount?: number;
  exceptionRejectedByTrustGateCount?: number;
  guardrailAppliedCount?: number;
  highRiskAlertsBefore?: number;
  highRiskAlertsAfter?: number;
  benignHighRiskBefore?: number;
  benignHighRiskAfter?: number;
  maliciousHighRiskBefore?: number;
  maliciousHighRiskAfter?: number;
  countByAnalystFeedbackStatus?: Record<string, number>;
}

export interface FusionEvaluationSummary {
  totalFusedAlerts?: number;
  countRequiringAnalystReview?: number;
  averageFusionRiskScore?: number;
  countByFusionDecision?: Record<string, number>;
  idAlignmentSummary?: {
    stage2RecordCount?: number;
    stage3PredictionCount?: number;
    matchedIdCount?: number;
    stage2OnlyCount?: number;
    stage3OutOfScopeCount?: number;
    overlapRateAgainstStage2?: number;
    overlapRateAgainstStage3?: number;
    alignmentStatus?: string;
  };
}
