import type { ReactNode } from 'react';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatPercent, formatScore } from '../utils/alertFilters';
import { ScoreComparison } from './ScoreComparison';

interface AlertDetailPanelProps {
  alert?: FeedbackAdjustedAlert;
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

export function AlertDetailPanel({ alert }: AlertDetailPanelProps) {
  if (!alert) {
    return (
      <aside className="panel detail-panel empty">
        <h2>Alert Detail</h2>
        <p>Select an alert to inspect evidence and feedback adjustment.</p>
      </aside>
    );
  }

  return (
    <aside className="panel detail-panel">
      <div className="panel-header">
        <h2>{alert.id}</h2>
        <span>{alert.fusionAttackType || 'Unknown'}</span>
      </div>

      <ScoreComparison alert={alert} />

      <EvidenceBlock title="Identity">
        <div className="detail-grid">
          <DetailItem label="Fusion attack type">{value(alert.fusionAttackType)}</DetailItem>
          <DetailItem label="Current risk">{formatScore(alert.currentRiskScore)}</DetailItem>
          <DetailItem label="Fusion risk">{formatScore(alert.fusionRiskScore)}</DetailItem>
          <DetailItem label="Confidence level">{value(alert.fusionConfidenceLevel)}</DetailItem>
          <DetailItem label="Requires review">{value(alert.requiresAnalystReview)}</DetailItem>
        </div>
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
          <DetailItem label="Model confidence">{formatPercent(alert.modelConfidence)}</DetailItem>
          <DetailItem label="Base risk">{formatScore(alert.baseRiskScore)}</DetailItem>
        </div>
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
        </div>
        <p>{alert.feedbackReason || 'No feedback reason recorded.'}</p>
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
