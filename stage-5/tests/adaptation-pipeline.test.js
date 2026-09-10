const test = require('node:test');
const assert = require('node:assert/strict');

const adaptationConfig = require('../config/adaptation-config.json');
const { calculateSimilarity } = require('../core/similarity-engine');
const {
  resolveEffectiveFeedbackEvents,
  aggregateHistoricalFeedback,
  chooseDominantFeedback,
} = require('../core/feedback-aggregation-engine');
const {
  applyGuardrails,
  adjustAlertsWithFeedback,
} = require('../core/feedback-engine');

function alert(id, overrides = {}) {
  return {
    id,
    fusionRiskScore: 80,
    fusionAttackType: 'Web Attack',
    fusionDecision: 'ML_ONLY_HIGH_CONFIDENCE',
    fusionConfidenceLevel: 'High',
    signatureSeverity: null,
    signatureId: null,
    requiresAnalystReview: true,
    flowFeatureSummary: {
      protocol: 'TCP',
      destinationPort: 80,
    },
    ...overrides,
  };
}

function feedback(feedbackId, alertId, feedbackType, overrides = {}) {
  return {
    feedbackId,
    alertId,
    eventType: 'feedback_submitted',
    feedbackType,
    analystId: 'analyst-test',
    timestamp: `2026-07-04T10:${String(Number(feedbackId.replace(/\D/g, '')) || 0).padStart(2, '0')}:00Z`,
    reason: 'test feedback',
    appliesToFutureSimilarAlerts: true,
    ...overrides,
  };
}

test('optional similarity fields missing on either side are excluded from the denominator', () => {
  const current = alert('AL-CURRENT', { signatureId: undefined });
  const historical = alert('AL-HISTORICAL', { signatureId: undefined });
  const result = calculateSimilarity(current, historical, adaptationConfig.similarity);

  assert.equal(result.passed, true);
  assert.equal(result.unavailableFields.includes('signatureId'), true);
  assert.equal(result.totalAvailableWeight, 0.85);
  assert.equal(result.score, 1);
});

test('missing required similarity fields fail similarity', () => {
  const current = alert('AL-CURRENT', { fusionAttackType: undefined });
  const historical = alert('AL-HISTORICAL');
  const result = calculateSimilarity(current, historical, adaptationConfig.similarity);

  assert.equal(result.passed, false);
  assert.equal(result.failureReason, 'missing_required_field');
});

test('high similarity with low agreement produces no historical adaptation', () => {
  const alerts = [
    alert('AL-TARGET'),
    alert('AL-H1'),
    alert('AL-H2'),
    alert('AL-H3'),
  ];
  const events = [
    feedback('FB-1', 'AL-H1', 'mark_false_positive'),
    feedback('FB-2', 'AL-H2', 'confirm_true_positive'),
    feedback('FB-3', 'AL-H3', 'confirm_true_positive'),
  ];

  const { adjustedAlerts } = adjustAlertsWithFeedback(alerts, [], [], adaptationConfig, {
    historicalFeedbackEvents: events,
  });
  const target = adjustedAlerts.find((item) => item.id === 'AL-TARGET');

  assert.equal(target.similarityMatched, true);
  assert.equal(target.adaptationEligible, false);
  assert.equal(target.operationalPriorityScore, target.detectionScore);
});

test('low similarity with high agreement produces no historical adaptation', () => {
  const alerts = [
    alert('AL-TARGET', { fusionAttackType: 'DoS' }),
    alert('AL-H1'),
    alert('AL-H2'),
    alert('AL-H3'),
  ];
  const events = [
    feedback('FB-1', 'AL-H1', 'mark_false_positive'),
    feedback('FB-2', 'AL-H2', 'mark_false_positive'),
    feedback('FB-3', 'AL-H3', 'mark_false_positive'),
  ];

  const { adjustedAlerts } = adjustAlertsWithFeedback(alerts, [], [], adaptationConfig, {
    historicalFeedbackEvents: events,
  });
  const target = adjustedAlerts.find((item) => item.id === 'AL-TARGET');

  assert.equal(target.similarityMatched, false);
  assert.equal(target.adaptationEligible, false);
  assert.equal(target.operationalPriorityScore, target.detectionScore);
});

test('reverted feedback is excluded from active aggregation', () => {
  const events = [
    feedback('FB-1', 'AL-H1', 'mark_false_positive'),
    {
      feedbackId: 'FB-2',
      eventType: 'feedback_reverted',
      revertsFeedbackId: 'FB-1',
      alertId: 'AL-H1',
      timestamp: '2026-07-04T10:05:00Z',
    },
  ];
  const resolved = resolveEffectiveFeedbackEvents(events);

  assert.equal(resolved.effectiveEvents.length, 0);
  assert.deepEqual(resolved.revertedFeedbackIds, ['FB-1']);
});

test('ties in historical feedback set conflictDetected and no dominant feedback', () => {
  const result = chooseDominantFeedback({
    mark_false_positive: 2,
    confirm_true_positive: 2,
  });

  assert.equal(result.conflictDetected, true);
  assert.equal(result.dominantFeedback, null);
});

test('workflow feedback does not contribute to future learning aggregation', () => {
  const alerts = new Map([
    ['AL-H1', alert('AL-H1')],
    ['AL-H2', alert('AL-H2')],
  ]);
  const aggregation = aggregateHistoricalFeedback(
    alert('AL-TARGET'),
    alerts,
    [
      feedback('FB-1', 'AL-H1', 'escalate'),
      feedback('FB-2', 'AL-H2', 'needs_investigation'),
    ],
    {
      ...adaptationConfig.aggregation,
      similarity: adaptationConfig.similarity,
    }
  );

  assert.equal(aggregation.learningFeedbackEventCount, 0);
  assert.equal(aggregation.matchedFeedbackCount, 0);
});

test('Expected Activity does not propagate without the stricter context gate', () => {
  const alerts = [
    alert('AL-TARGET'),
    alert('AL-H1'),
    alert('AL-H2'),
    alert('AL-H3'),
    alert('AL-H4'),
    alert('AL-H5'),
  ];
  const events = [
    feedback('FB-1', 'AL-H1', 'mark_expected_activity'),
    feedback('FB-2', 'AL-H2', 'mark_expected_activity'),
    feedback('FB-3', 'AL-H3', 'mark_expected_activity'),
    feedback('FB-4', 'AL-H4', 'mark_expected_activity'),
    feedback('FB-5', 'AL-H5', 'mark_expected_activity'),
  ];

  const { adjustedAlerts } = adjustAlertsWithFeedback(alerts, [], [], adaptationConfig, {
    historicalFeedbackEvents: events,
  });
  const target = adjustedAlerts.find((item) => item.id === 'AL-TARGET');

  assert.equal(target.dominantHistoricalFeedback, 'mark_expected_activity');
  assert.equal(target.adaptationEligible, false);
  assert.equal(target.operationalPriorityScore, target.detectionScore);
});

test('formal adaptive evaluation runs with manual exception memory disabled', () => {
  const alerts = [alert('AL-TARGET')];
  const exceptionMemory = [{
    exceptionId: 'EX-1',
    enabled: true,
    matchFields: {
      fusionAttackType: 'Web Attack',
      fusionDecision: 'ML_ONLY_HIGH_CONFIDENCE',
    },
    feedbackCount: 10,
    confidence: 1,
    riskAdjustment: -30,
  }];

  const { adjustedAlerts, useManualExceptionMemory } = adjustAlertsWithFeedback(
    alerts,
    [],
    exceptionMemory,
    adaptationConfig,
    { useManualExceptionMemory: false }
  );

  assert.equal(useManualExceptionMemory, false);
  assert.equal(adjustedAlerts[0].matchedExceptionId, null);
  assert.equal(adjustedAlerts[0].operationalPriorityScore, adjustedAlerts[0].detectionScore);
});

test('Detection Score remains immutable after repeated adaptation', () => {
  const alerts = [
    alert('AL-TARGET'),
    alert('AL-H1'),
    alert('AL-H2'),
    alert('AL-H3'),
  ];
  const events = [
    feedback('FB-1', 'AL-H1', 'mark_false_positive'),
    feedback('FB-2', 'AL-H2', 'mark_false_positive'),
    feedback('FB-3', 'AL-H3', 'mark_false_positive'),
  ];

  const first = adjustAlertsWithFeedback(alerts, [], [], adaptationConfig, {
    historicalFeedbackEvents: events,
  }).adjustedAlerts;
  const second = adjustAlertsWithFeedback(first, [], [], adaptationConfig, {
    historicalFeedbackEvents: events,
  }).adjustedAlerts;
  const target = second.find((item) => item.id === 'AL-TARGET');

  assert.equal(target.detectionScore, 80);
  assert.equal(target.fusionRiskScore, 80);
  assert.equal(target.operationalPriorityScore, 55);
});

test('guardrail caps adjustment before adding it to Detection Score and preserves Critical protection', () => {
  const result = applyGuardrails(
    alert('AL-TARGET', {
      fusionRiskScore: 95,
      signatureSeverity: 'Critical',
      fusionConfidenceLevel: 'High',
    }),
    -90,
    adaptationConfig.guardrails
  );

  assert.equal(result.cappedAdjustment, -30);
  assert.equal(result.operationalPriorityScore, 70);
  assert.equal(result.feedbackGuardrailsApplied.includes('critical_alert_floor_70'), true);
});
