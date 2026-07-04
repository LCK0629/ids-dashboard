import type { ReactNode } from 'react';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';
import {
  formatModelConfidenceScore,
  formatScore,
  isActionableAlert,
  isSuppressedOrResolved,
  recordTypeLabel,
} from '../utils/alertFilters';
import { FeedbackControls } from './FeedbackControls';
import { ScoreComparison } from './ScoreComparison';

interface AlertDetailPanelProps {
  alert?: FeedbackAdjustedAlert;
  onApplyFeedback?: (alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) => void;
  onResetFeedback?: (alert: FeedbackAdjustedAlert) => void;
}

function value(value: unknown): string {
  if (value === undefined || value === null || value === '') {
    return 'N/A';
  }
  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No';
  }
  return String(value);
}

function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

function EvidenceBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="evidence-block">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

export function AlertDetailPanel({ alert, onApplyFeedback, onResetFeedback }: AlertDetailPanelProps) {
  if (!alert) {
    return (
      <aside className="panel detail-panel empty">
        <h2>Detection Record Detail</h2>
        <p>Select a detection record to inspect evidence and feedback adjustment.</p>
      </aside>
    );
  }

  const classification = recordTypeLabel(alert);
  const classificationExplanation = isActionableAlert(alert)
    ? 'This record is promoted into the Active Alert Queue.'
    : isSuppressedOrResolved(alert)
      ? 'This record is retained for auditability but is not part of the default active alert queue.'
      : 'This record is retained for audit and evaluation. It is not necessarily an active alert unless promoted by risk score, signature evidence, fusion decision, or analyst-review requirement.';
  const originalPipelineRisk = Number(alert.stage5CurrentRiskScore ?? alert.currentRiskScore ?? 0);
  const interactiveCurrentRisk = Number(alert.currentRiskScore ?? 0);
  const interactiveAdjustment = interactiveCurrentRisk - originalPipelineRisk;
  const reviewBefore = Boolean(alert.stage5RequiresAnalystReview ?? alert.requiresAnalystReview);
  const reviewAfter = Boolean(alert.requiresAnalystReview);
  const guardrailResult = alert.localGuardrailMessage
    || (alert.feedbackGuardrailsApplied?.length
      ? `Existing pipeline guardrails: ${alert.feedbackGuardrailsApplied.join(', ')}`
      : 'No guardrail triggered in this session.');

  return (
    <aside className="panel detail-panel">
      <div className="panel-header">
        <h2>{alert.id}</h2>
        <span>{alert.fusionAttackType || 'Unknown'}</span>
      </div>

      <ScoreComparison alert={alert} />

      <FeedbackControls
        activeAction={alert.localFeedbackAction}
        disabled={!onApplyFeedback || !onResetFeedback}
        onApplyFeedback={(action) => onApplyFeedback?.(alert, action)}
        onResetFeedback={() => onResetFeedback?.(alert)}
      />

      <EvidenceBlock title="Feedback Impact">
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
          <DetailItem label="Guardrail result">{guardrailResult}</DetailItem>
        </div>
        <p>
          {alert.localFeedbackReason || 'No local analyst feedback applied in this session.'}
        </p>
        <p className="helper-text">
          Human feedback changes local dashboard priority only. No JSON files are modified and no model retraining is performed.
        </p>
      </EvidenceBlock>

      <EvidenceBlock title="Identity">
        <div className="detail-grid">
          <DetailItem label="Record classification">{classification}</DetailItem>
          <DetailItem label="Fusion attack type">{value(alert.fusionAttackType)}</DetailItem>
          <DetailItem label="Current risk">{formatScore(alert.currentRiskScore)}</DetailItem>
          <DetailItem label="Fusion risk">{formatScore(alert.fusionRiskScore)}</DetailItem>
          <DetailItem label="Confidence level">{value(alert.fusionConfidenceLevel)}</DetailItem>
          <DetailItem label="Requires review">{value(alert.requiresAnalystReview)}</DetailItem>
        </div>
        <p className="helper-text">{classificationExplanation}</p>
      </EvidenceBlock>

      <EvidenceBlock title="Signature Evidence">
        <div className="detail-grid">
          <DetailItem label="Signature hit">{value(alert.signatureHit)}</DetailItem>
          <DetailItem label="Signature ID">{value(alert.signatureId)}</DetailItem>
          <DetailItem label="Signature attack">{value(alert.signatureAttackType)}</DetailItem>
          <DetailItem label="Severity">{value(alert.signatureSeverity)}</DetailItem>
        </div>
        <p>{alert.signatureEvidence || 'No signature evidence available.'}</p>
      </EvidenceBlock>

      <EvidenceBlock title="ML Evidence">
        <div className="detail-grid">
          <DetailItem label="ML prediction">{value(alert.mlPredictedAttackType)}</DetailItem>
          <DetailItem label="XGBoost confidence score">{formatModelConfidenceScore(alert.modelConfidence)}</DetailItem>
          <DetailItem label="Base risk">{formatScore(alert.baseRiskScore)}</DetailItem>
        </div>
        <p className="helper-text">Uncalibrated model score, not certainty.</p>
      </EvidenceBlock>

      <EvidenceBlock title="Fusion Evidence">
        <div className="detail-grid">
          <DetailItem label="Fusion decision">{value(alert.fusionDecision)}</DetailItem>
        </div>
        <p>{alert.fusionEvidence || 'No fusion evidence available.'}</p>
      </EvidenceBlock>

      <EvidenceBlock title="Feedback Evidence">
        <div className="detail-grid">
          <DetailItem label="Feedback applied">{value(alert.feedbackApplied)}</DetailItem>
          <DetailItem label="Adjustment">{value(alert.feedbackAdjustment)}</DetailItem>
          <DetailItem label="Matched feedback">{value(alert.matchedFeedbackId)}</DetailItem>
          <DetailItem label="Matched exception">{value(alert.matchedExceptionId)}</DetailItem>
          <DetailItem label="Feedback status">{value(alert.analystFeedbackStatus)}</DetailItem>
          <DetailItem label="Local feedback">{value(alert.localFeedbackLabel)}</DetailItem>
        </div>
        <p>{alert.feedbackReason || 'No feedback reason recorded.'}</p>
        {alert.localFeedbackReason && <p>{alert.localFeedbackReason}</p>}
        {alert.localGuardrailMessage && <p className="guardrail-message">{alert.localGuardrailMessage}</p>}
        <div className="tag-list">
          {(alert.feedbackGuardrailsApplied || []).length
            ? alert.feedbackGuardrailsApplied?.map((guardrail) => <span key={guardrail}>{guardrail}</span>)
            : <span>no guardrail</span>}
        </div>
      </EvidenceBlock>

      <EvidenceBlock title="Ground Truth">
        <div className="detail-grid">
          <DetailItem label="Ground truth">{value(alert.groundTruth)}</DetailItem>
          <DetailItem label="True attack type">{value(alert.trueAttackType || alert.mappedAttackType)}</DetailItem>
          <DetailItem label="Raw label">{value(alert.rawLabel)}</DetailItem>
        </div>
      </EvidenceBlock>
    </aside>
  );
}
