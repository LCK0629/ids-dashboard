import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatModelConfidenceScore, formatScore } from '../utils/alertFilters';
import { ScoreComparison } from './ScoreComparison';

interface InvestigationsPanelProps {
  alert?: FeedbackAdjustedAlert;
}

function value(input: unknown): string {
  if (input === undefined || input === null || input === '') {
    return 'N/A';
  }
  return String(input);
}

export function InvestigationsPanel({ alert }: InvestigationsPanelProps) {
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
    ['Signature Detection', alert.signatureHit ? `Matched ${value(alert.signatureId)}` : 'No signature rule matched'],
    ['XGBoost Prediction', `${value(alert.mlPredictedAttackType)} at ${formatModelConfidenceScore(alert.modelConfidence)}`],
    ['Fusion Decision', `${value(alert.fusionDecision)} -> ${formatScore(alert.fusionRiskScore)}`],
    ['Feedback Adjustment', `${value(alert.analystFeedbackStatus)} -> ${formatScore(alert.currentRiskScore)}`],
  ];

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
      <div className="timeline">
        {timeline.map(([stage, description]) => (
          <article className="timeline-item" key={stage}>
            <span>{stage}</span>
            <strong>{description}</strong>
          </article>
        ))}
      </div>
      <div className="explain-panel">
        <h3>Current Evidence</h3>
        <p>{alert.feedbackReason || alert.fusionEvidence || 'No detailed evidence recorded.'}</p>
      </div>
    </section>
  );
}
