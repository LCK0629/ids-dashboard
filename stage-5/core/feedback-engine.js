const fs = require('fs');

function loadJsonFile(filePath, fallback = null) {
  if (!fs.existsSync(filePath)) {
    if (fallback !== null) {
      return fallback;
    }
    throw new Error(`JSON file not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function clampScore(score) {
  const numericScore = Number(score);
  if (Number.isNaN(numericScore)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function findDirectFeedback(alert, analystFeedback = []) {
  return analystFeedback.find((feedback) => feedback && String(feedback.alertId) === String(alert.id)) || null;
}

function matchesException(alert, exception) {
  if (!exception || !exception.enabled || !exception.matchFields) {
    return false;
  }

  return Object.entries(exception.matchFields).every(([field, expectedValue]) => {
    if (!(field in alert)) {
      return false;
    }
    return alert[field] === expectedValue;
  });
}

function findMatchingException(alert, exceptionMemory = []) {
  return exceptionMemory.find((exception) => matchesException(alert, exception)) || null;
}

function applyGuardrails(alert, proposedAdjustment) {
  let adjustment = Number(proposedAdjustment || 0);
  const guardrailsApplied = [];
  let requiresReviewDueToGuardrail = false;

  if (adjustment < -30) {
    adjustment = -30;
    guardrailsApplied.push('maximum_reduction_capped_at_30');
    requiresReviewDueToGuardrail = true;
  }

  let adjustedScore = clampScore(Number(alert.fusionRiskScore || 0) + adjustment);

  if (
    adjustment < 0
    && (alert.fusionConfidenceLevel === 'Critical' || alert.signatureSeverity === 'Critical')
    && adjustedScore < 70
  ) {
    adjustedScore = 70;
    guardrailsApplied.push('critical_alert_floor_70');
    requiresReviewDueToGuardrail = true;
  }

  if (adjustment < 0 && alert.fusionAttackType === 'Infiltration' && adjustedScore < 75) {
    adjustedScore = 75;
    guardrailsApplied.push('infiltration_floor_75');
    requiresReviewDueToGuardrail = true;
  }

  return {
    currentRiskScore: adjustedScore,
    feedbackAdjustment: adjustedScore - clampScore(alert.fusionRiskScore),
    feedbackGuardrailsApplied: guardrailsApplied,
    requiresReviewDueToGuardrail,
  };
}

function applyDirectFeedback(alert, feedback) {
  const feedbackType = feedback.feedbackType;
  const feedbackMap = {
    confirm_true_positive: {
      adjustment: 10,
      status: 'confirmed_true_positive',
      reason: 'Analyst confirmed this alert as a true positive.',
      forceReview: false,
    },
    mark_false_positive: {
      adjustment: -30,
      status: 'marked_false_positive',
      reason: 'Analyst marked this alert as a false positive.',
      forceReview: false,
    },
    mark_expected_activity: {
      adjustment: -30,
      status: 'marked_expected_activity',
      reason: 'Analyst marked this alert as expected activity.',
      forceReview: false,
    },
    needs_investigation: {
      adjustment: 0,
      status: 'needs_investigation',
      reason: 'Analyst requested continued investigation.',
      forceReview: true,
    },
    escalate: {
      adjustment: 15,
      status: 'escalated',
      reason: 'Analyst escalated this alert for higher priority review.',
      forceReview: true,
    },
  };

  const feedbackEffect = feedbackMap[feedbackType];
  if (!feedbackEffect) {
    return null;
  }

  const guarded = applyGuardrails(alert, feedbackEffect.adjustment);
  const guardrailLimited = guarded.feedbackGuardrailsApplied.length > 0;
  return {
    currentRiskScore: guarded.currentRiskScore,
    feedbackApplied: true,
    feedbackAdjustment: guarded.feedbackAdjustment,
    matchedFeedbackId: feedback.feedbackId,
    feedbackReason: `${feedbackEffect.reason} ${feedback.reason || ''}`.trim(),
    feedbackGuardrailsApplied: guarded.feedbackGuardrailsApplied,
    analystFeedbackStatus: guardrailLimited ? 'guardrail_limited_adjustment' : feedbackEffect.status,
    forceReview: feedbackEffect.forceReview || guarded.requiresReviewDueToGuardrail,
  };
}

function applyExceptionMemory(alert, exception) {
  if (!exception) {
    return null;
  }

  if (Number(exception.confidence || 0) < 0.6) {
    return {
      currentRiskScore: clampScore(alert.fusionRiskScore),
      feedbackApplied: false,
      feedbackAdjustment: 0,
      matchedExceptionId: exception.exceptionId,
      matchedExceptionType: exception.patternType,
      feedbackReason: 'Matching exception memory was ignored because confidence is below 0.6.',
      feedbackGuardrailsApplied: ['low_confidence_exception_ignored'],
      analystFeedbackStatus: 'ignored_low_confidence_exception',
      forceReview: false,
      ignoredException: true,
    };
  }

  if (Number(exception.feedbackCount || 0) < 3) {
    return {
      currentRiskScore: clampScore(alert.fusionRiskScore),
      feedbackApplied: false,
      feedbackAdjustment: 0,
      matchedExceptionId: exception.exceptionId,
      matchedExceptionType: exception.patternType,
      feedbackReason: 'Matching exception memory was ignored because feedbackCount is below 3.',
      feedbackGuardrailsApplied: ['insufficient_feedback_exception_ignored'],
      analystFeedbackStatus: 'ignored_insufficient_feedback',
      forceReview: false,
      ignoredException: true,
    };
  }

  const guarded = applyGuardrails(alert, exception.riskAdjustment);
  const guardrailLimited = guarded.feedbackGuardrailsApplied.length > 0;
  const scoreChanged = guarded.feedbackAdjustment !== 0;
  return {
    currentRiskScore: guarded.currentRiskScore,
    feedbackApplied: scoreChanged,
    feedbackAdjustment: guarded.feedbackAdjustment,
    matchedExceptionId: exception.exceptionId,
    matchedExceptionType: exception.patternType,
    feedbackReason: scoreChanged
      ? exception.reason || 'Exception memory matched this alert.'
      : 'Exception memory matched, but the score did not change after clamping.',
    feedbackGuardrailsApplied: guarded.feedbackGuardrailsApplied,
    analystFeedbackStatus: scoreChanged
      ? (guardrailLimited ? 'guardrail_limited_adjustment' : 'adjusted_by_exception_memory')
      : 'unchanged',
    forceReview: guarded.requiresReviewDueToGuardrail,
    ignoredException: false,
  };
}

function setReviewFlag(alert, currentRiskScore, forceReview) {
  if (forceReview) {
    return true;
  }
  return currentRiskScore >= 70;
}

function adjustAlertWithFeedback(alert, analystFeedback = [], exceptionMemory = []) {
  const directFeedback = findDirectFeedback(alert, analystFeedback);
  const matchingException = findMatchingException(alert, exceptionMemory);
  const baseRiskScore = clampScore(alert.fusionRiskScore);
  let result = {
    currentRiskScore: baseRiskScore,
    feedbackApplied: false,
    feedbackAdjustment: 0,
    matchedExceptionId: null,
    matchedExceptionType: null,
    matchedFeedbackId: null,
    feedbackReason: 'No direct feedback or exception memory matched this alert.',
    feedbackGuardrailsApplied: [],
    analystFeedbackStatus: 'unchanged',
    forceReview: false,
    ignoredException: false,
  };

  if (directFeedback) {
    const directResult = applyDirectFeedback(alert, directFeedback);
    if (directResult) {
      result = {
        ...result,
        ...directResult,
        matchedExceptionId: matchingException ? matchingException.exceptionId : null,
        matchedExceptionType: matchingException ? matchingException.patternType : null,
      };
      if (matchingException) {
        result.feedbackReason = `${result.feedbackReason} Matching exception ${matchingException.exceptionId} was recorded but not applied because direct analyst feedback takes priority.`;
      }
    }
  } else if (matchingException) {
    result = {
      ...result,
      ...applyExceptionMemory(alert, matchingException),
    };
  }

  const requiresAnalystReviewBeforeFeedback = Boolean(alert.requiresAnalystReview);
  const updatedReviewFlag = setReviewFlag(alert, result.currentRiskScore, result.forceReview);

  const adjustedAlert = {
    ...alert,
    requiresAnalystReviewBeforeFeedback,
    requiresAnalystReview: updatedReviewFlag,
    currentRiskScore: result.currentRiskScore,
    feedbackApplied: result.feedbackApplied,
    feedbackAdjustment: result.feedbackAdjustment,
    matchedExceptionId: result.matchedExceptionId || null,
    matchedExceptionType: result.matchedExceptionType || null,
    matchedFeedbackId: result.matchedFeedbackId || null,
    feedbackReason: result.feedbackReason,
    feedbackGuardrailsApplied: result.feedbackGuardrailsApplied || [],
    analystFeedbackStatus: result.analystFeedbackStatus,
  };

  return adjustedAlert;
}

function adjustAlertsWithFeedback(alerts, analystFeedback = [], exceptionMemory = []) {
  const alertIds = new Set((alerts || []).map((alert) => String(alert.id)));
  const unmatchedFeedback = (analystFeedback || []).filter((feedback) => !alertIds.has(String(feedback.alertId)));
  const adjustedAlerts = (alerts || [])
    .map((alert) => adjustAlertWithFeedback(alert, analystFeedback, exceptionMemory))
    .sort((a, b) => {
      if (b.currentRiskScore !== a.currentRiskScore) {
        return b.currentRiskScore - a.currentRiskScore;
      }
      if (a.requiresAnalystReview !== b.requiresAnalystReview) {
        return a.requiresAnalystReview ? -1 : 1;
      }
      return String(a.id).localeCompare(String(b.id));
    });

  return {
    adjustedAlerts,
    unmatchedFeedback,
  };
}

function incrementCounter(counter, key) {
  const safeKey = key || 'Unknown';
  counter[safeKey] = (counter[safeKey] || 0) + 1;
}

function averageScore(alerts, field) {
  if (!alerts.length) {
    return 0;
  }
  const total = alerts.reduce((sum, alert) => sum + Number(alert[field] || 0), 0);
  return Number((total / alerts.length).toFixed(2));
}

function summariseFeedbackResults(adjustedAlerts, unmatchedFeedback = [], groundTruth = null) {
  const summary = {
    totalAlerts: adjustedAlerts.length,
    alertsAdjusted: adjustedAlerts.filter((alert) => alert.feedbackAdjustment !== 0).length,
    alertsUnchanged: adjustedAlerts.filter((alert) => alert.feedbackAdjustment === 0).length,
    directFeedbackAppliedCount: adjustedAlerts.filter((alert) => alert.matchedFeedbackId).length,
    unmatchedDirectFeedbackCount: unmatchedFeedback.length,
    exceptionMemoryAppliedCount: adjustedAlerts.filter((alert) => (
      alert.matchedExceptionId
      && !alert.matchedFeedbackId
      && alert.feedbackApplied
      && ![
        'ignored_low_confidence_exception',
        'ignored_insufficient_feedback',
      ].includes(alert.analystFeedbackStatus)
    )).length,
    ignoredExceptionCount: adjustedAlerts.filter((alert) => (
      alert.analystFeedbackStatus === 'ignored_low_confidence_exception'
      || alert.analystFeedbackStatus === 'ignored_insufficient_feedback'
    )).length,
    guardrailAppliedCount: adjustedAlerts.filter((alert) => alert.feedbackGuardrailsApplied.length > 0).length,
    averageRiskBeforeFeedback: averageScore(adjustedAlerts, 'fusionRiskScore'),
    averageRiskAfterFeedback: averageScore(adjustedAlerts, 'currentRiskScore'),
    averageRiskChange: 0,
    highRiskThreshold: 70,
    highRiskAlertsBefore: adjustedAlerts.filter((alert) => alert.fusionRiskScore >= 70).length,
    highRiskAlertsAfter: adjustedAlerts.filter((alert) => alert.currentRiskScore >= 70).length,
    reviewQueueBefore: adjustedAlerts.filter((alert) => alert.requiresAnalystReviewBeforeFeedback).length,
    reviewQueueAfter: adjustedAlerts.filter((alert) => alert.requiresAnalystReview).length,
    benignHighRiskBefore: null,
    benignHighRiskAfter: null,
    maliciousHighRiskBefore: null,
    maliciousHighRiskAfter: null,
    reviewedBenignBefore: null,
    reviewedBenignAfter: null,
    reviewedMaliciousBefore: null,
    reviewedMaliciousAfter: null,
    truePositiveSuppressionCount: null,
    infiltrationAdjustedCount: adjustedAlerts.filter(
      (alert) => alert.fusionAttackType === 'Infiltration' && alert.feedbackAdjustment !== 0
    ).length,
    infiltrationGuardrailCount: adjustedAlerts.filter(
      (alert) => alert.feedbackGuardrailsApplied.includes('infiltration_floor_75')
    ).length,
    countByAnalystFeedbackStatus: {},
    notes: [
      'Ground truth is joined only after feedback adjustment for evaluation.',
      'This is a prototype feedback evaluation, not production IDS performance.',
      'The goal is to show workload and priority changes after simulated analyst feedback.',
    ],
  };

  summary.averageRiskChange = Number((summary.averageRiskAfterFeedback - summary.averageRiskBeforeFeedback).toFixed(2));

  for (const alert of adjustedAlerts) {
    incrementCounter(summary.countByAnalystFeedbackStatus, alert.analystFeedbackStatus);
  }

  if (groundTruth) {
    const evaluatedAlerts = adjustedAlerts
      .map((alert) => {
        const truth = groundTruth[String(alert.id)];
        if (!truth) {
          return null;
        }
        const label = truth.groundTruth || (truth.mappedAttackType === 'Benign' ? 'benign' : 'malicious');
        return {
          ...alert,
          groundTruthLabel: label,
        };
      })
      .filter(Boolean);

    const benignAlerts = evaluatedAlerts.filter((alert) => alert.groundTruthLabel === 'benign');
    const maliciousAlerts = evaluatedAlerts.filter((alert) => alert.groundTruthLabel === 'malicious');

    summary.evaluatedWithGroundTruthCount = evaluatedAlerts.length;
    summary.benignHighRiskBefore = benignAlerts.filter((alert) => alert.fusionRiskScore >= 70).length;
    summary.benignHighRiskAfter = benignAlerts.filter((alert) => alert.currentRiskScore >= 70).length;
    summary.maliciousHighRiskBefore = maliciousAlerts.filter((alert) => alert.fusionRiskScore >= 70).length;
    summary.maliciousHighRiskAfter = maliciousAlerts.filter((alert) => alert.currentRiskScore >= 70).length;
    summary.reviewedBenignBefore = benignAlerts.filter((alert) => alert.requiresAnalystReviewBeforeFeedback).length;
    summary.reviewedBenignAfter = benignAlerts.filter((alert) => alert.requiresAnalystReview).length;
    summary.reviewedMaliciousBefore = maliciousAlerts.filter((alert) => alert.requiresAnalystReviewBeforeFeedback).length;
    summary.reviewedMaliciousAfter = maliciousAlerts.filter((alert) => alert.requiresAnalystReview).length;
    summary.truePositiveSuppressionCount = maliciousAlerts.filter((alert) => (
      alert.fusionRiskScore >= 40
      && alert.currentRiskScore < 40
      && alert.feedbackAdjustment < 0
    )).length;
  }

  return summary;
}

module.exports = {
  loadJsonFile,
  clampScore,
  findDirectFeedback,
  matchesException,
  findMatchingException,
  applyGuardrails,
  applyDirectFeedback,
  applyExceptionMemory,
  adjustAlertWithFeedback,
  adjustAlertsWithFeedback,
  summariseFeedbackResults,
};
