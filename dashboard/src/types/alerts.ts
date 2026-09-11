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
  | 'exception-trust-gate';

export type AttackTypeFilter = 'all' | string;

export interface FlowAlertCounts {
  totalProcessedFlows: number;
  allDetectionRecords: number;
  activeAlerts: number;
  reviewRequiredAlerts: number;
  suppressedOrResolvedRecords: number;
  lowRiskRecords: number;
  highRiskRecords: number;
  feedbackAdjustedRecords: number;
  guardrailLimitedRecords: number;
  exceptionTrustGateRejectedRecords: number;
}

export interface FeedbackAdjustedAlert {
  id: string;
  detectionScore: number;
  operationalPriorityScore: number;
  flowFeatureSummary?: {
    protocol?: string | number;
    sourcePort?: number;
    destinationPort?: number;
    flowDuration?: number;
    totalFwdPackets?: number;
    totalBackwardPackets?: number;
    totalLengthFwdPackets?: number;
    totalLengthBwdPackets?: number;
    flowPacketsPerSecond?: number;
    flowBytesPerSecond?: number;
    packetLengthMean?: number;
    packetLengthMax?: number;
    fwdPacketLengthMean?: number;
    flowIatMean?: number;
    flowIatStd?: number;
    synFlagCount?: number;
    ackFlagCount?: number;
    pshFlagCount?: number;
  };
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
  mlRecordPresent?: boolean;
  mlPredictionStatus?: string;
  mlEvidenceAvailable?: boolean;
  mlFailureReason?: string | null;
  mlSchemaMode?: string;
  mlPredictedClassIndex?: number | null;
  signatureHit?: boolean;
  signatureId?: string | null;
  signatureName?: string | null;
  signatureAttackType?: string | null;
  signatureSeverity?: string | null;
  signatureSummary?: string | null;
  signaturePlainExplanation?: string | null;
  matchedConditionsReadable?: string[];
  signatureTechnicalDetails?: {
    ruleId?: string;
    ruleName?: string;
    predictedAttackType?: string;
    severity?: string;
    validationStatus?: string;
    rationale?: string;
    matchedConditions?: string[];
  } | null;
  signatureEvidence?: string;
  mlPredictedAttackType?: string | null;
  modelConfidence?: number | null;
  classProbabilities?: Record<string, number> | null;
  secondBestClass?: string | null;
  predictionMargin?: number | null;
  modelProvenance?: Record<string, string | null> | null;
  mlThreatEvidenceScore?: number | null;
  mlExplanation?: Record<string, unknown> | null;
  matchedFeedbackId?: string | null;
  matchedExceptionId?: string | null;
  matchedExceptionType?: string | null;
  feedbackReason?: string;
  feedbackGuardrailsApplied?: string[];
  guardrailInterventions?: Array<Record<string, unknown>>;
  analystFeedbackStatus?: string;
  feedbackRecorded?: boolean;
  priorityAdjusted?: boolean;
  proposedFeedbackAdjustment?: number;
  cappedFeedbackAdjustment?: number;
  adaptationSource?: string;
  adaptationEligible?: boolean;
  adaptationEligibilityReason?: string;
  adaptationExplanation?: string;
  similarityMatched?: boolean;
  similarityReason?: string;
  matchedHistoricalFeedbackCount?: number;
  matchedHistoricalFeedbackIds?: string[];
  dominantHistoricalFeedback?: string | null;
  historicalAgreementRatio?: number;
  conflictDetected?: boolean;
  lowEvidenceCoverageCount?: number;
  lowSimilarityCount?: number;
  stage5CurrentRiskScore?: number;
  stage5RequiresAnalystReview?: boolean;
  localFeedbackAction?: string;
  localFeedbackLabel?: string;
  localFeedbackReason?: string;
  localFeedbackTimestamp?: string;
  localGuardrailMessage?: string;
}

export interface FeedbackEvaluationSummary {
  totalAlerts?: number;
  heldOutAlertCount?: number;
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
