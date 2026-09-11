import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction, LocalFeedbackMap, LocalFeedbackOverride, SessionKpis } from '../types/feedback';
import { isActionableAlert, isSuppressedOrResolved } from './alertFilters';
import { calculateSessionPreview, SESSION_PREVIEW_ACTION_POLICY } from './sessionPreview.js';

export function createSessionPreviewOverride(
  alert: FeedbackAdjustedAlert,
  action: AnalystFeedbackAction
): LocalFeedbackOverride {
  const config = SESSION_PREVIEW_ACTION_POLICY[action];
  return {
    alertId: alert.id,
    action,
    scoreDelta: config.delta,
    reviewRequired: config.forceReview,
    reason: config.reason,
    timestamp: new Date().toISOString(),
  };
}

export function applySessionPreviewOverride(
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
    operationalPriorityScore: stage5CurrentRiskScore,
    currentRiskScore: stage5CurrentRiskScore,
    pipelineOperationalPriorityScore: stage5CurrentRiskScore,
    sessionPreviewPriorityScore: undefined,
    localFeedbackScoreDelta: undefined,
  };

  if (!override) {
    return baseAlert;
  }

  const preview = calculateSessionPreview(baseAlert, override.action);

  return {
    ...baseAlert,
    currentRiskScore: preview.sessionPreviewPriorityScore,
    sessionPreviewPriorityScore: preview.sessionPreviewPriorityScore,
    localFeedbackScoreDelta: preview.appliedDelta,
    requiresAnalystReview: preview.reviewRequired,
    localFeedbackAction: override.action,
    localFeedbackLabel: SESSION_PREVIEW_ACTION_POLICY[override.action].label,
    localFeedbackReason: override.reason,
    localFeedbackTimestamp: override.timestamp,
    localGuardrailMessage: preview.guardrailMessage,
  };
}

export function applySessionPreviewOverrides(
  alerts: FeedbackAdjustedAlert[],
  feedbackMap: LocalFeedbackMap
): FeedbackAdjustedAlert[] {
  return alerts.map((alert) => applySessionPreviewOverride(alert, feedbackMap[alert.id]));
}

export function calculateSessionKpis(
  visibleRecords: FeedbackAdjustedAlert[],
  allDetectionRecords: FeedbackAdjustedAlert[],
  feedbackMap: LocalFeedbackMap,
  replayIndex: number,
  totalRecords: number
): SessionKpis {
  const totalRisk = visibleRecords.reduce(
    (sum, alert) => sum + Number(alert.sessionPreviewPriorityScore ?? alert.operationalPriorityScore ?? 0),
    0,
  );
  const beforeRiskTotal = allDetectionRecords.reduce(
    (sum, alert) => sum + Number(alert.stage5CurrentRiskScore ?? alert.currentRiskScore ?? 0),
    0
  );
  const afterRiskTotal = allDetectionRecords.reduce(
    (sum, alert) => sum + Number(alert.sessionPreviewPriorityScore ?? alert.operationalPriorityScore ?? 0),
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
    highRiskRecords: visibleRecords.filter(
      (alert) => Number(alert.sessionPreviewPriorityScore ?? alert.operationalPriorityScore ?? 0) >= 70,
    ).length,
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
