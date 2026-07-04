export type FilterKey =
  | 'active-alerts'
  | 'all-records'
  | 'requires-review'
  | 'feedback-applied'
  | 'high-risk'
  | 'medium-risk'
  | 'low-risk'
  | 'suppressed-resolved'
  | 'signature-hit'
  | 'signature-ml-disagree'
  | 'guardrail-applied'
  | 'benign'
  | 'malicious';

export type AttackTypeFilter = 'all' | string;

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
  stage5CurrentRiskScore?: number;
  localFeedbackAction?: string;
  localFeedbackLabel?: string;
  localFeedbackReason?: string;
  localFeedbackTimestamp?: string;
  localGuardrailMessage?: string;
}

export interface FeedbackEvaluationSummary {
  totalAlerts?: number;
  alertsAdjusted?: number;
  alertsUnchanged?: number;
  directFeedbackAppliedCount?: number;
  unmatchedDirectFeedbackCount?: number;
  exceptionMemoryAppliedCount?: number;
  ignoredExceptionCount?: number;
  reviewQueueBefore?: number;
  reviewQueueAfter?: number;
  averageRiskBeforeFeedback?: number;
  averageRiskAfterFeedback?: number;
  averageRiskChange?: number;
  scoreAdjustmentGuardrailCount?: number;
  exceptionRejectedByTrustGateCount?: number;
  guardrailAppliedCount?: number;
  highRiskAlertsBefore?: number;
  highRiskAlertsAfter?: number;
  benignHighRiskBefore?: number;
  benignHighRiskAfter?: number;
  maliciousHighRiskBefore?: number;
  maliciousHighRiskAfter?: number;
  reviewedBenignBefore?: number;
  reviewedBenignAfter?: number;
  reviewedMaliciousBefore?: number;
  reviewedMaliciousAfter?: number;
  truePositiveSuppressionCount?: number;
  evaluatedWithGroundTruthCount?: number;
  countByAnalystFeedbackStatus?: Record<string, number>;
}

export interface FusionEvaluationSummary {
  totalFusedAlerts?: number;
  countRequiringAnalystReview?: number;
  averageFusionRiskScore?: number;
  countByFusionDecision?: Record<string, number>;
  signatureMlAgreementCount?: number;
  signatureMlDisagreementCount?: number;
  mlOnlyAlertCount?: number;
  signatureOnlyAlertCount?: number;
  groundTruthEvaluation?: {
    simpleFusionAccuracy?: number;
    classificationMetrics?: {
      accuracy?: number;
      macroF1?: number;
      weightedF1?: number;
    };
    binaryDetectionMetrics?: {
      precision?: number;
      recall?: number;
      f1?: number;
    };
    riskPrioritisationMetrics?: {
      top50Precision?: number;
      top100Precision?: number;
      top200Precision?: number;
      highRiskThresholdPrecision?: number;
    };
    analystReviewMetrics?: {
      reviewPrecision?: number;
      reviewRate?: number;
    };
  };
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
