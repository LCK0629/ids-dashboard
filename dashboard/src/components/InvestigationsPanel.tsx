import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';
import { formatModelConfidenceScore, formatScore } from '../utils/alertFilters';
import {
  analystRecommendation,
  buildFeatureInterpretation,
  buildInvestigationTimeline,
  evidenceSource,
  signatureGapNote,
} from '../utils/investigation';
import { FeatureSummaryPanel } from './FeatureSummaryPanel';
import { FeedbackControls } from './FeedbackControls';
import { FeedbackImpactPanel } from './FeedbackImpactPanel';
import { ScoreComparison } from './ScoreComparison';

interface InvestigationsPanelProps {
  alert?: FeedbackAdjustedAlert;
  onApplyFeedback?: (alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) => void;
  onResetFeedback?: (alert: FeedbackAdjustedAlert) => void;
}

function value(input: unknown): string {
  if (input === undefined || input === null || input === '') {
    return 'N/A';
  }
  return String(input);
}

export function InvestigationsPanel({ alert, onApplyFeedback, onResetFeedback }: InvestigationsPanelProps) {
  if (!alert) {
    return (
      <section className="panel full-panel">
        <div className="panel-header">
          <h2>Investigations</h2>
          <span>No detection record selected</span>
        </div>
      </section>
    );
  }

  const timeline = [
    ...buildInvestigationTimeline(alert),
  ];
  const interpretations = buildFeatureInterpretation(alert);
  const gapNote = signatureGapNote(alert);
  const recommendation = analystRecommendation(alert);

  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div>
          <h2>Investigation Case</h2>
          <p>{alert.id} · {alert.fusionAttackType || 'Unknown'}</p>
        </div>
        <span className="impact-pill">{alert.requiresAnalystReview ? 'Review required' : 'No review required'}</span>
      </div>
      <ScoreComparison alert={alert} />
      <div className="investigation-section">
        <h3>Selected Record Summary</h3>
        <div className="metric-grid compact">
          <article className="metric-card">
            <span>Fusion attack type</span>
            <strong>{value(alert.fusionAttackType)}</strong>
          </article>
          <article className="metric-card">
            <span>Evidence source</span>
            <strong>{evidenceSource(alert)}</strong>
          </article>
          <article className="metric-card">
            <span>Current risk</span>
            <strong>{formatScore(alert.currentRiskScore)}</strong>
          </article>
          <article className="metric-card">
            <span>Review status</span>
            <strong>{alert.requiresAnalystReview ? 'Review required' : 'No immediate review'}</strong>
          </article>
        </div>
      </div>
      <div className="investigation-section">
        <h3>Feature Summary</h3>
        <p className="helper-text">
          Key flow-level features used for investigation context. Missing values are shown as N/A.
        </p>
        <FeatureSummaryPanel alert={alert} />
      </div>
      <div className="investigation-section">
        <h3>Feature Interpretation</h3>
        <div className="insight-list">
          {interpretations.map((item) => <p key={item}>{item}</p>)}
        </div>
      </div>
      <div className="timeline">
        {timeline.map(([stage, description]) => (
          <article className="timeline-item" key={stage}>
            <span>{stage}</span>
            <strong>{description}</strong>
          </article>
        ))}
      </div>
      {gapNote && (
        <div className="explain-panel warning-panel">
          <h3>Signature Gap Note</h3>
          <p>{gapNote}</p>
        </div>
      )}
      <div className="grid two investigation-grid">
        <div className="explain-panel">
          <h3>Signature Result</h3>
          <p>
            {alert.signatureHit
              ? alert.signaturePlainExplanation || alert.signatureSummary || 'A prototype signature matched this flow.'
              : 'No signature rule matched this flow. This does not prove the flow is benign.'}
          </p>
          {(alert.matchedConditionsReadable || []).length > 0 && (
            <ul className="condition-list">
              {alert.matchedConditionsReadable?.map((condition) => <li key={condition}>{condition}</li>)}
            </ul>
          )}
        </div>
        <div className="explain-panel">
          <h3>ML Result</h3>
          <p>
            ML prediction: {value(alert.mlPredictedAttackType)} at {formatModelConfidenceScore(alert.modelConfidence)}.
            The ML model uses flow-level numerical features, not packet payload. The confidence score is an uncalibrated XGBoost output and should not be interpreted as certainty.
          </p>
        </div>
        <div className="explain-panel">
          <h3>Fusion Decision</h3>
          <p>
            Fusion decision: {value(alert.fusionDecision)}. Fusion risk score: {formatScore(alert.fusionRiskScore)}.
            Current risk score: {formatScore(alert.currentRiskScore)}. Evidence source: {evidenceSource(alert)}.
          </p>
        </div>
        <div className="explain-panel">
          <h3>Feedback History</h3>
          <p>{alert.feedbackReason || 'No pipeline feedback reason recorded.'}</p>
          <p>
            Local analyst feedback: {value(alert.localFeedbackLabel)}. Score guardrail or trust-gate evidence: {alert.localGuardrailMessage || value(alert.feedbackGuardrailsApplied?.join(', '))}.
          </p>
          <p className="helper-text">
            Human feedback can change review priority, but this dashboard does not write feedback back to JSON files or retrain the model.
          </p>
        </div>
      </div>
      <div className="investigation-section feedback-decision-section">
        <h3>Analyst Feedback Decision</h3>
        <p className="helper-text">
          Feedback submitted here is session-only and updates dashboard priority. It does not write back to JSON files or retrain the model.
        </p>
        <FeedbackControls
          activeAction={alert.localFeedbackAction}
          disabled={!onApplyFeedback || !onResetFeedback}
          onApplyFeedback={(action) => onApplyFeedback?.(alert, action)}
          onResetFeedback={() => onResetFeedback?.(alert)}
        />
        <FeedbackImpactPanel alert={alert} />
      </div>
      <div className="explain-panel">
        <h3>Analyst Recommendation</h3>
        <p>{recommendation}</p>
      </div>
    </section>
  );
}
