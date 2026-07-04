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
        <span>Fusion score</span>
        <strong>{formatScore(alert.fusionRiskScore)}</strong>
      </div>
      <div>
        <span>Current score</span>
        <strong>{formatScore(alert.currentRiskScore)}</strong>
      </div>
      <div>
        <span>Feedback adjustment</span>
        <strong className={direction}>{adjustment > 0 ? `+${adjustment}` : adjustment}</strong>
      </div>
      <p>Fusion score is the machine-generated score before analyst feedback.</p>
      <p>Current score is the feedback-adjusted score used for prioritisation.</p>
    </section>
  );
}
