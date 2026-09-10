import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatScore } from '../utils/alertFilters';

interface ScoreComparisonProps {
  alert: FeedbackAdjustedAlert;
}

export function ScoreComparison({ alert }: ScoreComparisonProps) {
  const adjustment = Number(alert.feedbackAdjustment ?? 0);
  const direction = adjustment > 0 ? 'increased' : adjustment < 0 ? 'decreased' : 'unchanged';

  return (
    <section className="score-comparison">
      <div>
        <span>Detection Score</span>
        <strong>{formatScore(alert.detectionScore)}</strong>
      </div>
      <div>
        <span>Operational Priority</span>
        <strong>{formatScore(alert.operationalPriorityScore)}</strong>
      </div>
      <div>
        <span>Feedback adjustment</span>
        <strong className={direction}>{adjustment > 0 ? `+${adjustment}` : adjustment}</strong>
      </div>
      <p>Detection Score preserves the automated Signature and ML result.</p>
      <p>Operational Priority is the Stage 5 value used for queue ranking.</p>
    </section>
  );
}
