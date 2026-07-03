import type { FeedbackAdjustedAlert, FilterKey } from '../types/alerts';

export function isHighRisk(alert: FeedbackAdjustedAlert): boolean {
  return Number(alert.currentRiskScore ?? 0) >= 70;
}

export function isAdjusted(alert: FeedbackAdjustedAlert): boolean {
  return Boolean(alert.feedbackApplied) || Number(alert.feedbackAdjustment ?? 0) !== 0;
}

export function requiresReview(alert: FeedbackAdjustedAlert): boolean {
  return Boolean(alert.requiresAnalystReview);
}

function isGuardrailApplied(alert: FeedbackAdjustedAlert): boolean {
  return Boolean(alert.feedbackGuardrailsApplied?.length)
    || alert.analystFeedbackStatus === 'guardrail_limited_adjustment';
}

function isBenign(alert: FeedbackAdjustedAlert): boolean {
  const label = alert.groundTruth || alert.trueAttackType || alert.mappedAttackType || alert.fusionAttackType;
  return String(label || '').toLowerCase() === 'benign';
}

function isMalicious(alert: FeedbackAdjustedAlert): boolean {
  const groundTruth = String(alert.groundTruth || '').toLowerCase();
  if (groundTruth === 'malicious') {
    return true;
  }
  if (groundTruth === 'benign') {
    return false;
  }
  const label = alert.trueAttackType || alert.mappedAttackType || alert.fusionAttackType;
  return Boolean(label && label !== 'Benign');
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
    switch (filter) {
      case 'requires-review':
        return requiresReview(alert);
      case 'feedback-applied':
        return isAdjusted(alert);
      case 'high-risk':
        return isHighRisk(alert);
      case 'infiltration':
        return alert.fusionAttackType === 'Infiltration' || alert.signatureAttackType === 'Infiltration';
      case 'signature-ml-disagree':
        return alert.fusionDecision === 'SIGNATURE_ML_DISAGREE';
      case 'guardrail-applied':
        return isGuardrailApplied(alert);
      case 'benign':
        return isBenign(alert);
      case 'malicious':
        return isMalicious(alert);
      case 'all':
      default:
        return true;
    }
  });
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
