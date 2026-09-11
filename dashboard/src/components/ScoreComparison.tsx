import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatScore } from '../utils/alertFilters';

interface ScoreComparisonProps {
  alert: FeedbackAdjustedAlert;
}

export function ScoreComparison({ alert }: ScoreComparisonProps) {
  const adjustment = Number(alert.feedbackAdjustment ?? 0);
  const direction = adjustment > 0 ? 'increased' : adjustment < 0 ? 'decreased' : 'unchanged';
  const pipelinePriority = Number(alert.pipelineOperationalPriorityScore ?? alert.operationalPriorityScore);
  const sessionPriority = alert.sessionPreviewPriorityScore;

  return (
    <section className={`score-comparison ${sessionPriority !== undefined ? 'has-session-preview' : ''}`}>
      <div>
        <span>Operational Priority</span>
        <strong className="primary-priority-score">{formatScore(pipelinePriority)}</strong>
      </div>
      <div>
        <span>Detection Score</span>
        <strong className="secondary-detection-score">{formatScore(alert.detectionScore)}</strong>
      </div>
      <div>
        <span>Historical HITL adjustment</span>
        <strong className={direction}>{adjustment > 0 ? `+${adjustment}` : adjustment}</strong>
      </div>
      {sessionPriority !== undefined && (
        <div className="session-preview-score">
          <span>Session Preview Priority</span>
          <strong>{formatScore(sessionPriority)}</strong>
        </div>
      )}
      <p>Detection Score preserves the automated Signature and ML result.</p>
      <p>Operational Priority is the Stage 5 pipeline value used for queue ranking. Session Preview is temporary and separate.</p>
    </section>
  );
}
