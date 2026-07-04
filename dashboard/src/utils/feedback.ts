import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction, LocalFeedbackMap, LocalFeedbackOverride, SessionKpis } from '../types/feedback';
import { isActionableAlert, isSuppressedOrResolved } from './alertFilters';

const actionConfig: Record<AnalystFeedbackAction, { delta: number; review: boolean; reason: string }> = {
  CONFIRMED_THREAT: {
    delta: 10,
    review: true,
    reason: 'Analyst confirmed this alert as a likely true positive.',
  },
  FALSE_POSITIVE: {
    delta: -30,
    review: false,
    reason: 'Analyst marked this alert as a false positive.',
  },
  EXPECTED_ACTIVITY: {
    delta: -30,
    review: false,
    reason: 'Analyst marked the behaviour as expected activity.',
  },
  NEEDS_INVESTIGATION: {
    delta: 0,
    review: true,
    reason: 'Analyst requested further investigation.',
  },
  ESCALATED: {
    delta: 15,
    review: true,
    reason: 'Analyst escalated this alert for urgent review.',
  },
};

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function labelForAction(action: AnalystFeedbackAction): string {
  return action
    .toLowerCase()
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

export function createLocalFeedbackOverride(
  alert: FeedbackAdjustedAlert,
  action: AnalystFeedbackAction
): LocalFeedbackOverride {
  const config = actionConfig[action];
  return {
    alertId: alert.id,
    action,
    scoreDelta: config.delta,
    reviewRequired: config.review,
    reason: config.reason,
    timestamp: new Date().toISOString(),
  };
}

export function applyLocalFeedbackOverride(
  alert: FeedbackAdjustedAlert,
  override?: LocalFeedbackOverride
): FeedbackAdjustedAlert {
  const stage5CurrentRiskScore = Number(alert.stage5CurrentRiskScore ?? alert.currentRiskScore ?? 0);
  const stage5RequiresAnalystReview = Boolean(
    alert.stage5RequiresAnalystReview ?? alert.requiresAnalystReview
  );
  const baseAlert = {
    ...alert,
    stage5CurrentRiskScore,
    stage5RequiresAnalystReview,
  };

  if (!override) {
    return baseAlert;
  }

  let nextScore = clampScore(stage5CurrentRiskScore + override.scoreDelta);
  let reviewRequired = override.reviewRequired;
  const guardrailMessages: string[] = [];
  const isReduction = override.scoreDelta < 0;

  if (isReduction && alert.fusionConfidenceLevel === 'Critical' && nextScore < 70) {
    nextScore = 70;
    reviewRequired = true;
    guardrailMessages.push('critical evidence');
  }

  if (isReduction && alert.fusionAttackType === 'Infiltration' && nextScore < 75) {
    nextScore = 75;
    reviewRequired = true;
    guardrailMessages.push('Infiltration evidence');
  }

  if (alert.fusionDecision === 'SIGNATURE_ML_DISAGREE') {
    reviewRequired = true;
    guardrailMessages.push('signature/ML disagreement');
  }

  const guardrailMessage = guardrailMessages.length
    ? `Guardrail applied: risk score floor or review status preserved due to ${guardrailMessages.join('; ')}.`
    : undefined;

  return {
    ...baseAlert,
    currentRiskScore: nextScore,
    requiresAnalystReview: reviewRequired || nextScore >= 70,
    localFeedbackAction: override.action,
    localFeedbackLabel: labelForAction(override.action),
    localFeedbackReason: override.reason,
    localFeedbackTimestamp: override.timestamp,
    localGuardrailMessage: guardrailMessage,
  };
}

export function applyLocalFeedbackOverrides(
  alerts: FeedbackAdjustedAlert[],
  feedbackMap: LocalFeedbackMap
): FeedbackAdjustedAlert[] {
  return alerts.map((alert) => applyLocalFeedbackOverride(alert, feedbackMap[alert.id]));
}

export function calculateSessionKpis(
  visibleRecords: FeedbackAdjustedAlert[],
  allDetectionRecords: FeedbackAdjustedAlert[],
  feedbackMap: LocalFeedbackMap,
  replayIndex: number,
  totalRecords: number
): SessionKpis {
  const totalRisk = visibleRecords.reduce((sum, alert) => sum + Number(alert.currentRiskScore ?? 0), 0);
  const beforeRiskTotal = allDetectionRecords.reduce(
    (sum, alert) => sum + Number(alert.stage5CurrentRiskScore ?? alert.currentRiskScore ?? 0),
    0
  );
  const afterRiskTotal = allDetectionRecords.reduce(
    (sum, alert) => sum + Number(alert.currentRiskScore ?? 0),
    0
  );
  const feedbackValues = Object.values(feedbackMap);
  const averageBefore = allDetectionRecords.length
    ? Number((beforeRiskTotal / allDetectionRecords.length).toFixed(2))
    : 0;
  const averageAfter = allDetectionRecords.length
    ? Number((afterRiskTotal / allDetectionRecords.length).toFixed(2))
    : 0;
  return {
    visibleRecords: visibleRecords.length,
    allDetectionRecords: allDetectionRecords.length,
    activeAlerts: allDetectionRecords.filter(isActionableAlert).length,
    suppressedResolved: allDetectionRecords.filter(isSuppressedOrResolved).length,
    reviewedInSession: feedbackValues.length,
    localFeedbackApplied: feedbackValues.length,
    averageCurrentRisk: visibleRecords.length ? Number((totalRisk / visibleRecords.length).toFixed(2)) : 0,
    highRiskRecords: visibleRecords.filter((alert) => Number(alert.currentRiskScore ?? 0) >= 70).length,
    requiresReview: visibleRecords.filter((alert) => alert.requiresAnalystReview).length,
    falsePositivesMarked: feedbackValues.filter((feedback) => feedback.action === 'FALSE_POSITIVE').length,
    expectedActivityMarked: feedbackValues.filter((feedback) => feedback.action === 'EXPECTED_ACTIVITY').length,
    confirmedThreats: feedbackValues.filter((feedback) => feedback.action === 'CONFIRMED_THREAT').length,
    escalatedAlerts: feedbackValues.filter((feedback) => feedback.action === 'ESCALATED').length,
    needsInvestigation: feedbackValues.filter((feedback) => feedback.action === 'NEEDS_INVESTIGATION').length,
    averageRiskBeforeLocalFeedback: averageBefore,
    averageRiskAfterLocalFeedback: averageAfter,
    averageRiskChange: Number((averageAfter - averageBefore).toFixed(2)),
    reviewRequiredBeforeLocalFeedback: allDetectionRecords.filter(
      (alert) => Boolean(alert.stage5RequiresAnalystReview ?? alert.requiresAnalystReview)
    ).length,
    reviewRequiredAfterLocalFeedback: allDetectionRecords.filter((alert) => alert.requiresAnalystReview).length,
    guardrailsTriggered: allDetectionRecords.filter((alert) => Boolean(alert.localGuardrailMessage)).length,
    replayProgress: `${Math.min(replayIndex, totalRecords)} / ${totalRecords}`,
  };
}
