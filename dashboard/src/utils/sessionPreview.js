export const SESSION_NOTE_MAX_LENGTH = 500;

export const SESSION_PREVIEW_ACTION_POLICY = Object.freeze({
  CONFIRMED_THREAT: Object.freeze({
    stage5FeedbackType: 'confirm_true_positive',
    category: 'learning',
    label: 'Confirm Threat',
    delta: 10,
    forceReview: true,
    reason: 'Analyst confirmed this alert as a likely true positive.',
  }),
  FALSE_POSITIVE: Object.freeze({
    stage5FeedbackType: 'mark_false_positive',
    category: 'learning',
    label: 'False Positive',
    delta: -30,
    forceReview: false,
    reason: 'Analyst marked this alert as a false positive.',
  }),
  EXPECTED_ACTIVITY: Object.freeze({
    stage5FeedbackType: 'mark_expected_activity',
    category: 'learning',
    label: 'Expected Activity',
    delta: -15,
    forceReview: false,
    reason: 'Analyst marked the behaviour as expected activity.',
  }),
  NEEDS_INVESTIGATION: Object.freeze({
    stage5FeedbackType: 'needs_investigation',
    category: 'workflow',
    label: 'Needs Investigation',
    delta: 0,
    forceReview: true,
    reason: 'Analyst requested further investigation.',
  }),
  UNCERTAIN: Object.freeze({
    stage5FeedbackType: 'uncertain',
    category: 'workflow',
    label: 'Uncertain',
    delta: 0,
    forceReview: true,
    reason: 'Analyst marked this alert as uncertain.',
  }),
  ESCALATED: Object.freeze({
    stage5FeedbackType: 'escalate',
    category: 'workflow',
    label: 'Escalate',
    delta: 15,
    forceReview: true,
    reason: 'Analyst escalated this alert for urgent review.',
  }),
  DUPLICATE: Object.freeze({
    stage5FeedbackType: 'duplicate',
    category: 'workflow',
    label: 'Duplicate',
    delta: 0,
    forceReview: false,
    reason: 'Analyst marked this alert as a duplicate workflow item.',
  }),
});

export const LEARNING_FEEDBACK_ACTIONS = Object.freeze([
  'CONFIRMED_THREAT',
  'FALSE_POSITIVE',
  'EXPECTED_ACTIVITY',
]);

export const WORKFLOW_ACTIONS = Object.freeze([
  'NEEDS_INVESTIGATION',
  'UNCERTAIN',
  'ESCALATED',
  'DUPLICATE',
]);

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function calculateSessionPreview(alert, action) {
  const policy = SESSION_PREVIEW_ACTION_POLICY[action];
  if (!policy) {
    throw new Error(`Unsupported session-preview action: ${action}`);
  }

  const pipelinePriority = Number(
    alert.stage5CurrentRiskScore ?? alert.operationalPriorityScore ?? alert.currentRiskScore ?? 0,
  );
  let nextPriority = clampScore(pipelinePriority + policy.delta);
  let reviewRequired = policy.forceReview;
  const guardrailReasons = [];
  const isReduction = policy.delta < 0;

  if (
    isReduction
    && (alert.fusionConfidenceLevel === 'Critical' || alert.signatureSeverity === 'Critical')
    && nextPriority < 70
  ) {
    nextPriority = 70;
    reviewRequired = true;
    guardrailReasons.push('Critical detection-score floor');
  }

  if (isReduction && alert.fusionAttackType === 'Infiltration' && nextPriority < 75) {
    nextPriority = 75;
    reviewRequired = true;
    guardrailReasons.push('Infiltration detection-score floor');
  }

  if (alert.fusionDecision === 'SIGNATURE_ML_DISAGREE') {
    reviewRequired = true;
    guardrailReasons.push('signature/ML disagreement review preservation');
  }

  return {
    pipelineOperationalPriorityScore: pipelinePriority,
    sessionPreviewPriorityScore: nextPriority,
    proposedDelta: policy.delta,
    appliedDelta: nextPriority - pipelinePriority,
    reviewRequired: reviewRequired || nextPriority >= 70,
    guardrailMessage: guardrailReasons.length
      ? `Session guardrail applied: ${guardrailReasons.join('; ')}.`
      : undefined,
  };
}

export function boundSessionNote(value) {
  return String(value ?? '').slice(0, SESSION_NOTE_MAX_LENGTH);
}

export function normalizeSessionNote(value) {
  return boundSessionNote(value).trim();
}
