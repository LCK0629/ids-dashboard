import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystAlertV1 } from '../types/dashboardData';

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

export function adaptAnalystAlertForLegacyComponents(alert: AnalystAlertV1): FeedbackAdjustedAlert {
  const flow = alert.flowFeatures;
  const signature = alert.signatureEvidence;
  const ml = alert.mlEvidence;
  const adaptation = alert.adaptation;
  const workflow = alert.workflow;

  return {
    id: alert.identity.id,
    detectionScore: alert.automatedDetection.detectionScore,
    operationalPriorityScore: adaptation.operationalPriorityScore,
    flowFeatureSummary: {
      protocol: flow.protocol ?? undefined,
      sourcePort: numberValue(flow.sourcePort),
      destinationPort: numberValue(flow.destinationPort),
      flowDuration: numberValue(flow.flowDuration),
      totalFwdPackets: numberValue(flow.totalFwdPackets),
      totalBackwardPackets: numberValue(flow.totalBackwardPackets),
      totalLengthFwdPackets: numberValue(flow.totalLengthFwdPackets),
      totalLengthBwdPackets: numberValue(flow.totalLengthBwdPackets),
      flowPacketsPerSecond: numberValue(flow.flowPacketsPerSecond),
      flowBytesPerSecond: numberValue(flow.flowBytesPerSecond),
      packetLengthMean: numberValue(flow.packetLengthMean),
      packetLengthMax: numberValue(flow.packetLengthMax),
      fwdPacketLengthMean: numberValue(flow.fwdPacketLengthMean),
      flowIatMean: numberValue(flow.flowIatMean),
      flowIatStd: numberValue(flow.flowIatStd),
      synFlagCount: numberValue(flow.synFlagCount),
      ackFlagCount: numberValue(flow.ackFlagCount),
      pshFlagCount: numberValue(flow.pshFlagCount),
    },
    fusionRiskScore: alert.automatedDetection.detectionScore,
    currentRiskScore: adaptation.operationalPriorityScore,
    feedbackApplied: adaptation.priorityAdjusted,
    feedbackRecorded: adaptation.feedbackRecorded,
    priorityAdjusted: adaptation.priorityAdjusted,
    feedbackAdjustment: adaptation.appliedAdjustment,
    proposedFeedbackAdjustment: adaptation.proposedAdjustment,
    cappedFeedbackAdjustment: adaptation.cappedAdjustment,
    requiresAnalystReview: workflow.requiresAnalystReview,
    requiresAnalystReviewBeforeFeedback: workflow.requiresAnalystReviewBeforeFeedback,
    fusionAttackType: alert.automatedDetection.attackType,
    fusionDecision: alert.automatedDetection.fusionDecision,
    fusionEvidence: alert.automatedDetection.fusionExplanation,
    fusionConfidenceLevel: alert.automatedDetection.confidenceLevel ?? undefined,
    signatureHit: signature.hit,
    signatureId: signature.ruleId,
    signatureName: signature.ruleName,
    signatureAttackType: signature.attackType,
    signatureSeverity: signature.severity,
    signatureSummary: signature.explanation,
    signaturePlainExplanation: signature.explanation,
    matchedConditionsReadable: signature.matchedConditions,
    signatureTechnicalDetails: signature.technicalDetail
      ? {
        ruleId: signature.ruleId ?? undefined,
        ruleName: signature.ruleName ?? undefined,
        predictedAttackType: signature.attackType ?? undefined,
        severity: signature.severity ?? undefined,
        validationStatus: signature.technicalDetail.validationStatus ?? undefined,
        rationale: signature.technicalDetail.rationale ?? undefined,
        matchedConditions: signature.matchedConditions,
      }
      : null,
    signatureEvidence: signature.explanation ?? undefined,
    mlRecordPresent: ml.recordPresent,
    mlPredictionStatus: ml.predictionStatus,
    mlEvidenceAvailable: ml.evidenceAvailable,
    mlFailureReason: ml.failureReason,
    mlSchemaMode: ml.schemaMode,
    mlPredictedClassIndex: ml.predictedClassIndex,
    mlPredictedAttackType: ml.predictedAttackType,
    modelConfidence: ml.modelConfidence,
    classProbabilities: ml.classProbabilities,
    secondBestClass: ml.secondBestClass,
    predictionMargin: ml.predictionMargin,
    modelProvenance: ml.modelProvenance as Record<string, string | null> | null,
    mlThreatEvidenceScore: ml.threatEvidenceScore,
    mlExplanation: ml.explanation as unknown as Record<string, unknown>,
    matchedFeedbackId: workflow.matchedFeedbackId,
    feedbackReason: adaptation.explanation,
    feedbackGuardrailsApplied: adaptation.guardrailsApplied,
    guardrailInterventions: adaptation.guardrailInterventions,
    analystFeedbackStatus: workflow.analystFeedbackStatus,
    adaptationSource: adaptation.source,
    adaptationEligible: adaptation.eligible,
    adaptationEligibilityReason: adaptation.eligibilityReason,
    adaptationExplanation: adaptation.explanation,
    similarityMatched: adaptation.similarityMatched,
    similarityReason: adaptation.similarityReason,
    matchedHistoricalFeedbackCount: adaptation.matchedHistoricalFeedbackCount,
    matchedHistoricalFeedbackIds: adaptation.matchedHistoricalFeedbackIds,
    dominantHistoricalFeedback: adaptation.dominantHistoricalFeedback,
    historicalAgreementRatio: adaptation.historicalAgreementRatio,
    conflictDetected: adaptation.conflictDetected,
    lowEvidenceCoverageCount: adaptation.lowEvidenceCoverageRejectionCount,
    lowSimilarityCount: adaptation.lowSimilarityRejectionCount,
    stage5CurrentRiskScore: adaptation.operationalPriorityScore,
    stage5RequiresAnalystReview: workflow.requiresAnalystReview,
  };
}

export function adaptAnalystAlertsForLegacyComponents(alerts: AnalystAlertV1[]): FeedbackAdjustedAlert[] {
  return alerts.map(adaptAnalystAlertForLegacyComponents);
}
