import type { ReactNode } from 'react';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatScore, isExceptionTrustGateRejected, isScoreGuardrailApplied } from '../utils/alertFilters';

interface FeedbackImpactPanelProps {
  alert: FeedbackAdjustedAlert;
}

function value(input: unknown): string {
  if (input === undefined || input === null || input === '') {
    return 'N/A';
  }
  if (typeof input === 'boolean') {
    return input ? 'Yes' : 'No';
  }
  return String(input);
}

function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

export function FeedbackImpactPanel({ alert }: FeedbackImpactPanelProps) {
  const originalPipelineRisk = Number(alert.stage5CurrentRiskScore ?? alert.currentRiskScore ?? 0);
  const interactiveCurrentRisk = Number(alert.currentRiskScore ?? 0);
  const interactiveAdjustment = interactiveCurrentRisk - originalPipelineRisk;
  const reviewBefore = Boolean(alert.stage5RequiresAnalystReview ?? alert.requiresAnalystReview);
  const reviewAfter = Boolean(alert.requiresAnalystReview);
  const scoreGuardrailResult = alert.localGuardrailMessage
    || (isScoreGuardrailApplied(alert)
      ? `Score guardrail applied: ${(alert.feedbackGuardrailsApplied || []).join(', ') || 'local feedback guardrail'}`
      : 'No score guardrail triggered in this session.');
  const trustGateResult = isExceptionTrustGateRejected(alert)
    ? `Exception trust gate rejected: ${(alert.feedbackGuardrailsApplied || []).join(', ')}`
    : 'No exception trust-gate rejection recorded.';

  return (
    <div className="feedback-impact-panel">
      <div className="detail-grid">
        <DetailItem label="Before feedback">{formatScore(originalPipelineRisk)}</DetailItem>
        <DetailItem label="After feedback">{formatScore(interactiveCurrentRisk)}</DetailItem>
        <DetailItem label="Fusion risk score">{formatScore(alert.fusionRiskScore)}</DetailItem>
        <DetailItem label="Score adjustment">
          {interactiveAdjustment > 0 ? `+${interactiveAdjustment}` : interactiveAdjustment}
        </DetailItem>
        <DetailItem label="Review status before">{value(reviewBefore)}</DetailItem>
        <DetailItem label="Review status after">{value(reviewAfter)}</DetailItem>
        <DetailItem label="Local analyst feedback">{value(alert.localFeedbackLabel)}</DetailItem>
        <DetailItem label="Score guardrail result">{scoreGuardrailResult}</DetailItem>
        <DetailItem label="Exception trust gate">{trustGateResult}</DetailItem>
      </div>
      <p>
        {alert.localFeedbackReason || 'No local analyst feedback applied in this session.'}
      </p>
      <p className="helper-text">
        Human feedback changes local dashboard priority only. No JSON files are modified and no model retraining is performed.
      </p>
    </div>
  );
}
