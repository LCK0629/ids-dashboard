import type { AttackTypeFilter, FeedbackAdjustedAlert, FilterKey, FlowAlertCounts } from '../types/alerts';

export function isHighRisk(alert: FeedbackAdjustedAlert): boolean {
  return Number(alert.currentRiskScore ?? 0) >= 70;
}

export function isAdjusted(alert: FeedbackAdjustedAlert): boolean {
  return Boolean(alert.feedbackApplied) || Number(alert.feedbackAdjustment ?? 0) !== 0;
}

export function requiresReview(alert: FeedbackAdjustedAlert): boolean {
  return Boolean(alert.requiresAnalystReview);
}

const scoreGuardrailCodes = [
  'maximum_reduction_capped_at_30',
  'critical_alert_floor_70',
  'infiltration_floor_75',
];

const exceptionTrustGateCodes = [
  'low_confidence_exception_ignored',
  'insufficient_feedback_exception_ignored',
];

export function isScoreGuardrailApplied(alert: FeedbackAdjustedAlert): boolean {
  const guardrails = alert.feedbackGuardrailsApplied || [];
  return alert.analystFeedbackStatus === 'guardrail_limited_adjustment'
    || scoreGuardrailCodes.some((code) => guardrails.includes(code))
    || Boolean(alert.localGuardrailMessage);
}

export function isExceptionTrustGateRejected(alert: FeedbackAdjustedAlert): boolean {
  const guardrails = alert.feedbackGuardrailsApplied || [];
  return alert.analystFeedbackStatus === 'ignored_low_confidence_exception'
    || alert.analystFeedbackStatus === 'ignored_insufficient_feedback'
    || exceptionTrustGateCodes.some((code) => guardrails.includes(code));
}

export function isSignatureMlDisagree(alert: FeedbackAdjustedAlert): boolean {
  const decision = String(alert.fusionDecision || '').toLowerCase();
  return decision.includes('disagree') || decision.includes('conflict');
}

export function isActionableAlert(alert: FeedbackAdjustedAlert): boolean {
  const riskScore = Number(alert.currentRiskScore ?? 0);
  const decision = String(alert.fusionDecision || '');
  return Boolean(alert.requiresAnalystReview)
    || riskScore >= 40
    || alert.signatureHit === true
    || (decision !== '' && decision !== 'LOW_RISK_BENIGN');
}

export function isSuppressedOrResolved(alert: FeedbackAdjustedAlert): boolean {
  const riskScore = Number(alert.currentRiskScore ?? 0);
  const status = String(alert.analystFeedbackStatus || alert.localFeedbackAction || '').toLowerCase();
  const resolvedStatus = status.includes('false_positive')
    || status.includes('false positive')
    || status.includes('expected_activity')
    || status.includes('expected activity')
    || status.includes('low_risk_benign')
    || status.includes('low risk benign')
    || status.includes('benign');
  return riskScore === 0
    || resolvedStatus
    || (!alert.requiresAnalystReview && riskScore < 40);
}

export const isSuppressedOrResolvedRecord = isSuppressedOrResolved;

export function getFlowAlertCounts(records: FeedbackAdjustedAlert[]): FlowAlertCounts {
  return {
    totalProcessedFlows: records.length,
    allDetectionRecords: records.length,
    activeAlerts: records.filter(isActionableAlert).length,
    reviewRequiredAlerts: records.filter((record) => Boolean(record.requiresAnalystReview)).length,
    suppressedOrResolvedRecords: records.filter(isSuppressedOrResolved).length,
    lowRiskRecords: records.filter((record) => {
      const score = Number(record.currentRiskScore ?? 0);
      return score > 0 && score < 40;
    }).length,
    highRiskRecords: records.filter((record) => Number(record.currentRiskScore ?? 0) >= 70).length,
    feedbackAdjustedRecords: records.filter(isAdjusted).length,
    guardrailLimitedRecords: records.filter(isScoreGuardrailApplied).length,
    exceptionTrustGateRejectedRecords: records.filter(isExceptionTrustGateRejected).length,
  };
}

export function recordTypeLabel(alert: FeedbackAdjustedAlert): string {
  if (isActionableAlert(alert)) {
    return 'Actionable Alert';
  }
  if (isSuppressedOrResolved(alert)) {
    return 'Suppressed / Resolved Record';
  }
  return 'Detection Record';
}

export function recordStatusBadges(alert: FeedbackAdjustedAlert): string[] {
  const badges: string[] = [];
  const status = String(alert.analystFeedbackStatus || alert.localFeedbackAction || '').toLowerCase();
  if (isSuppressedOrResolved(alert)) badges.push('Suppressed / Resolved');
  if (Number(alert.currentRiskScore ?? 0) === 0) badges.push('Suppressed');
  if (status.includes('false_positive') || status.includes('false positive')) badges.push('False Positive');
  if (status.includes('expected_activity') || status.includes('expected activity')) badges.push('Expected Activity');
  if (Number(alert.currentRiskScore ?? 0) > 0 && Number(alert.currentRiskScore ?? 0) < 40) badges.push('Low Risk');
  if (isScoreGuardrailApplied(alert)) badges.push('Score Guardrail Applied');
  if (isExceptionTrustGateRejected(alert)) badges.push('Exception Trust Gate Rejected');
  return [...new Set(badges)];
}

export function getGroundTruthLabel(alert: FeedbackAdjustedAlert): 'benign' | 'malicious' | null {
  const groundTruth = String(alert.groundTruth || '').toLowerCase();
  if (groundTruth === 'benign') {
    return 'benign';
  }
  if (groundTruth === 'malicious') {
    return 'malicious';
  }

  const mapped = String(alert.trueAttackType || alert.mappedAttackType || alert.rawLabel || '').toLowerCase();
  if (!mapped) {
    return null;
  }
  if (mapped === 'benign') {
    return 'benign';
  }
  return 'malicious';
}

function isBenign(alert: FeedbackAdjustedAlert): boolean {
  return getGroundTruthLabel(alert) === 'benign';
}

function isMalicious(alert: FeedbackAdjustedAlert): boolean {
  return getGroundTruthLabel(alert) === 'malicious';
}

export function sortAlerts(alerts: FeedbackAdjustedAlert[]): FeedbackAdjustedAlert[] {
  return [...alerts].sort((a, b) => {
    const riskDiff = Number(b.currentRiskScore ?? 0) - Number(a.currentRiskScore ?? 0);
    if (riskDiff !== 0) {
      return riskDiff;
    }
    if (Boolean(a.requiresAnalystReview) !== Boolean(b.requiresAnalystReview)) {
      return a.requiresAnalystReview ? -1 : 1;
    }
    return String(a.id).localeCompare(String(b.id), undefined, { numeric: true });
  });
}

export function filterAlerts(alerts: FeedbackAdjustedAlert[], filter: FilterKey): FeedbackAdjustedAlert[] {
  return alerts.filter((alert) => {
    const riskScore = Number(alert.currentRiskScore ?? 0);
    switch (filter) {
      case 'active-alerts':
        return isActionableAlert(alert);
      case 'all-records':
        return true;
      case 'requires-review':
        return requiresReview(alert);
      case 'feedback-applied':
        return isAdjusted(alert);
      case 'high-risk':
        return riskScore >= 70;
      case 'medium-risk':
        return riskScore >= 40 && riskScore < 70;
      case 'low-risk':
        return riskScore > 0 && riskScore < 40;
      case 'suppressed-resolved':
        return isSuppressedOrResolved(alert);
      case 'signature-hit':
        return alert.signatureHit === true;
      case 'signature-ml-disagree':
        return isSignatureMlDisagree(alert);
      case 'guardrail-applied':
        return isScoreGuardrailApplied(alert);
      case 'exception-trust-gate':
        return isExceptionTrustGateRejected(alert);
      case 'benign':
        return isBenign(alert);
      case 'malicious':
        return isMalicious(alert);
      default:
        return isActionableAlert(alert);
    }
  });
}

export function alertAttackType(alert: FeedbackAdjustedAlert): string {
  return alert.fusionAttackType || alert.signatureAttackType || alert.mlPredictedAttackType || 'Unknown';
}

export function attackTypeOptions(alerts: FeedbackAdjustedAlert[]): string[] {
  return [...new Set(alerts.map(alertAttackType))]
    .filter((attackType) => attackType.trim().length > 0)
    .sort((a, b) => a.localeCompare(b));
}

export function filterAlertsByAttackType(
  alerts: FeedbackAdjustedAlert[],
  attackType: AttackTypeFilter
): FeedbackAdjustedAlert[] {
  if (attackType === 'all') {
    return alerts;
  }
  return alerts.filter((alert) => alertAttackType(alert) === attackType);
}

export function formatScore(score?: number | null): string {
  if (score === undefined || score === null || Number.isNaN(Number(score))) {
    return 'N/A';
  }
  return String(Math.round(Number(score)));
}

export function formatPercent(value?: number | null): string {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'N/A';
  }
  return `${(Number(value) * 100).toFixed(1)}%`;
}

export function formatModelConfidenceScore(value?: number | null): string {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'N/A';
  }
  const numericValue = Number(value);
  if (numericValue >= 1) {
    return '100.0%';
  }
  if (numericValue >= 0.999) {
    return '99.9%+';
  }
  return `${(numericValue * 100).toFixed(1)}%`;
}
