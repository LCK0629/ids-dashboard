export function getHistoricalAdjustmentPresentation(adaptation) {
  const proposed = Number(adaptation.proposedAdjustment || 0);
  const capped = Number(adaptation.cappedAdjustment || 0);
  const applied = Number(adaptation.appliedAdjustment || 0);
  const history = adaptation.diagnostics?.historicalFeedback;
  const similarity = adaptation.diagnostics?.similarity;

  if (adaptation.conflictDetected) {
    return { key: 'conflict', label: 'Conflict / no adjustment', tone: 'warning' };
  }
  if (
    adaptation.guardrailsApplied?.length > 0
    && (proposed !== capped || proposed !== applied)
  ) {
    return { key: 'guardrail_limited', label: 'Guardrail limited', tone: 'warning' };
  }
  if (adaptation.priorityAdjusted) {
    return {
      key: 'adjusted',
      label: `Adjusted ${applied > 0 ? '+' : ''}${applied}`,
      tone: applied > 0 ? 'positive' : 'neutral',
    };
  }
  if (!adaptation.diagnostics?.evaluated) {
    return { key: 'not_evaluated', label: 'Historical adaptation not evaluated', tone: 'muted' };
  }
  if (Number(history?.candidateLearningFeedbackCount || 0) === 0) {
    return { key: 'no_history', label: 'No historical adjustment', tone: 'muted' };
  }
  if (Number(similarity?.matchedCount || 0) === 0) {
    return { key: 'no_applicable_history', label: 'No applicable history', tone: 'muted' };
  }
  if (!adaptation.eligible) {
    return { key: 'insufficient_history', label: 'Insufficient history', tone: 'muted' };
  }
  return { key: 'no_adjustment', label: 'No historical adjustment', tone: 'muted' };
}

const workflowActionLabels = {
  NEEDS_INVESTIGATION: 'Needs investigation',
  UNCERTAIN: 'Uncertain',
  ESCALATED: 'Escalated',
  DUPLICATE: 'Duplicate',
};

export function getReviewWorkflowPresentation(alert, analystAlert) {
  if (workflowActionLabels[alert.localFeedbackAction]) {
    return {
      key: alert.localFeedbackAction.toLowerCase(),
      label: workflowActionLabels[alert.localFeedbackAction],
      tone: alert.localFeedbackAction === 'ESCALATED' ? 'warning' : 'neutral',
    };
  }
  if (analystAlert?.automatedDetection?.detectorState === 'disagreement') {
    return { key: 'detector_conflict', label: 'Detector conflict', tone: 'warning' };
  }
  if (alert.localGuardrailMessage && alert.requiresAnalystReview) {
    return { key: 'guardrail_review', label: 'Guardrail preserves review', tone: 'warning' };
  }
  return alert.requiresAnalystReview
    ? { key: 'review_required', label: 'Review required', tone: 'warning' }
    : { key: 'no_review', label: 'No review flag', tone: 'muted' };
}
