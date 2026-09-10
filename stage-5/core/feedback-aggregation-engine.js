const { calculateSimilarity, getValueByPath, isAvailable } = require('./similarity-engine');

const DEFAULT_LEARNING_TYPES = [
  'mark_false_positive',
  'confirm_true_positive',
  'mark_expected_activity',
];

const WORKFLOW_TYPES = [
  'escalate',
  'needs_investigation',
  'duplicate',
  'uncertain',
];

function normalizeFeedbackEvent(event, index = 0) {
  return {
    ...event,
    feedbackId: event.feedbackId || `FB-GENERATED-${index + 1}`,
    eventType: event.eventType || 'feedback_submitted',
    appliesToFutureSimilarAlerts: event.appliesToFutureSimilarAlerts !== false,
  };
}

function timestampValue(event) {
  const value = Date.parse(event.timestamp || '');
  return Number.isNaN(value) ? 0 : value;
}

function resolveEffectiveFeedbackEvents(events = []) {
  const normalizedEvents = events.map(normalizeFeedbackEvent);
  const reverted = new Set();
  const superseded = new Set();

  for (const event of normalizedEvents) {
    if (event.revertsFeedbackId) {
      reverted.add(String(event.revertsFeedbackId));
    }
    if (event.supersedesFeedbackId) {
      superseded.add(String(event.supersedesFeedbackId));
    }
  }

  const submittedEvents = normalizedEvents
    .filter((event) => event.eventType === 'feedback_submitted')
    .filter((event) => !reverted.has(String(event.feedbackId)))
    .filter((event) => !superseded.has(String(event.feedbackId)))
    .sort((a, b) => timestampValue(a) - timestampValue(b));

  const effectiveByAlert = new Map();
  for (const event of submittedEvents) {
    if (!event.alertId) {
      continue;
    }
    effectiveByAlert.set(String(event.alertId), event);
  }

  return {
    allEvents: normalizedEvents,
    effectiveEvents: [...effectiveByAlert.values()],
    effectiveByAlert,
    revertedFeedbackIds: [...reverted],
    supersededFeedbackIds: [...superseded],
    auditEventCount: normalizedEvents.length,
  };
}

function isLearningFeedback(event, config = {}) {
  const learningTypes = config.learningFeedbackTypes || DEFAULT_LEARNING_TYPES;
  if (WORKFLOW_TYPES.includes(event.feedbackType)) {
    return false;
  }
  return learningTypes.includes(event.feedbackType);
}

function hasExactContext(currentAlert, historicalAlert, fields = []) {
  const unavailable = [];
  const differed = [];

  for (const field of fields) {
    const currentValue = getValueByPath(currentAlert, field);
    const historicalValue = getValueByPath(historicalAlert, field);
    if (!isAvailable(currentValue) || !isAvailable(historicalValue)) {
      unavailable.push(field);
      continue;
    }
    if (String(currentValue).trim().toLowerCase() !== String(historicalValue).trim().toLowerCase()) {
      differed.push(field);
    }
  }

  return {
    passed: unavailable.length === 0 && differed.length === 0,
    unavailable,
    differed,
  };
}

function chooseDominantFeedback(counts) {
  const entries = Object.entries(counts).filter(([, count]) => count > 0);
  if (!entries.length) {
    return {
      dominantFeedback: null,
      dominantCount: 0,
      agreementRatio: 0,
      conflictDetected: false,
    };
  }

  const highestCount = Math.max(...entries.map(([, count]) => count));
  const winners = entries.filter(([, count]) => count === highestCount);
  if (winners.length > 1) {
    return {
      dominantFeedback: null,
      dominantCount: highestCount,
      agreementRatio: Number((highestCount / entries.reduce((sum, [, count]) => sum + count, 0)).toFixed(4)),
      conflictDetected: true,
    };
  }

  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  return {
    dominantFeedback: winners[0][0],
    dominantCount: highestCount,
    agreementRatio: Number((highestCount / total).toFixed(4)),
    conflictDetected: false,
  };
}

function aggregateHistoricalFeedback(currentAlert, alertsById, effectiveEvents = [], config = {}) {
  const counts = {
    mark_false_positive: 0,
    confirm_true_positive: 0,
    mark_expected_activity: 0,
  };
  const matchedFeedback = [];
  const similarityAttempts = [];
  const learningEvents = effectiveEvents.filter((event) => (
    event.appliesToFutureSimilarAlerts !== false && isLearningFeedback(event, config)
  ));

  for (const event of learningEvents) {
    if (!event.alertId || String(event.alertId) === String(currentAlert.id)) {
      continue;
    }

    const historicalAlert = alertsById.get(String(event.alertId));
    if (!historicalAlert) {
      similarityAttempts.push({
        feedbackId: event.feedbackId,
        passed: false,
        reason: 'historical_alert_not_found',
      });
      continue;
    }

    const similarity = calculateSimilarity(currentAlert, historicalAlert, config.similarity || {});
    similarityAttempts.push({
      feedbackId: event.feedbackId,
      alertId: event.alertId,
      feedbackType: event.feedbackType,
      similarity,
    });

    if (!similarity.passed) {
      continue;
    }

    counts[event.feedbackType] = (counts[event.feedbackType] || 0) + 1;
    matchedFeedback.push({
      feedbackId: event.feedbackId,
      alertId: event.alertId,
      feedbackType: event.feedbackType,
      similarityScore: similarity.score,
      similarityReasons: similarity.reasons,
      exactExpectedActivityContext: hasExactContext(
        currentAlert,
        historicalAlert,
        (config.expectedActivity && config.expectedActivity.requiredExactContextFields) || []
      ),
    });
  }

  const dominant = chooseDominantFeedback(counts);
  const matchedFeedbackCount = matchedFeedback.length;
  const averageSimilarity = matchedFeedbackCount
    ? Number((matchedFeedback.reduce((sum, item) => sum + item.similarityScore, 0) / matchedFeedbackCount).toFixed(4))
    : 0;

  return {
    matchedFeedbackCount,
    counts,
    falsePositiveCount: counts.mark_false_positive || 0,
    confirmedThreatCount: counts.confirm_true_positive || 0,
    expectedActivityCount: counts.mark_expected_activity || 0,
    dominantFeedback: dominant.dominantFeedback,
    dominantFeedbackCount: dominant.dominantCount,
    agreementRatio: dominant.agreementRatio,
    conflictDetected: dominant.conflictDetected,
    averageSimilarity,
    matchedFeedback,
    sourceFeedbackIds: matchedFeedback.map((item) => item.feedbackId),
    similarityAttempts,
    learningFeedbackEventCount: learningEvents.length,
  };
}

function buildGeneratedHistoricalMemory(alertsById, effectiveEvents = [], config = {}) {
  const grouped = new Map();
  const events = effectiveEvents.filter((event) => (
    event.appliesToFutureSimilarAlerts !== false && isLearningFeedback(event, config)
  ));

  for (const event of events) {
    const alert = alertsById.get(String(event.alertId));
    if (!alert) {
      continue;
    }

    const profile = {
      fusionAttackType: alert.fusionAttackType || null,
      fusionDecision: alert.fusionDecision || null,
      protocol: getValueByPath(alert, 'flowFeatureSummary.protocol') || null,
      destinationPort: getValueByPath(alert, 'flowFeatureSummary.destinationPort') || null,
      signatureId: alert.signatureId || null,
    };
    const key = JSON.stringify(profile);
    if (!grouped.has(key)) {
      grouped.set(key, {
        profile,
        counts: {},
        sourceFeedbackIds: [],
        sourceAlertIds: [],
        reasons: [],
      });
    }
    const group = grouped.get(key);
    group.counts[event.feedbackType] = (group.counts[event.feedbackType] || 0) + 1;
    group.sourceFeedbackIds.push(event.feedbackId);
    group.sourceAlertIds.push(event.alertId);
    if (event.reason) {
      group.reasons.push(event.reason);
    }
  }

  return [...grouped.values()].map((group, index) => {
    const dominant = chooseDominantFeedback(group.counts);
    return {
      memoryId: `HM-${String(index + 1).padStart(4, '0')}`,
      profile: group.profile,
      effectiveFeedbackCount: group.sourceFeedbackIds.length,
      falsePositiveCount: group.counts.mark_false_positive || 0,
      confirmedThreatCount: group.counts.confirm_true_positive || 0,
      expectedActivityCount: group.counts.mark_expected_activity || 0,
      dominantFeedback: dominant.dominantFeedback,
      agreementRatio: dominant.agreementRatio,
      conflictDetected: dominant.conflictDetected,
      sourceFeedbackIds: group.sourceFeedbackIds,
      sourceAlertIds: [...new Set(group.sourceAlertIds)],
      exampleReasons: group.reasons.slice(0, 3),
      derivedFrom: 'analyst-feedback events',
    };
  });
}

module.exports = {
  normalizeFeedbackEvent,
  resolveEffectiveFeedbackEvents,
  isLearningFeedback,
  hasExactContext,
  chooseDominantFeedback,
  aggregateHistoricalFeedback,
  buildGeneratedHistoricalMemory,
};
