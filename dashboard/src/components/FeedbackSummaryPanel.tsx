import type { FeedbackEvaluationSummary } from '../types/alerts';
import { formatScore } from '../utils/alertFilters';

interface FeedbackSummaryPanelProps {
  summary: FeedbackEvaluationSummary;
}

function value(input: number | undefined): string {
  return input === undefined ? 'N/A' : String(input);
}

export function FeedbackSummaryPanel({ summary }: FeedbackSummaryPanelProps) {
  const metrics = [
    ['Records adjusted', value(summary.alertsAdjusted)],
    ['Direct feedback count', value(summary.directFeedbackAppliedCount)],
    ['Exception memory applied', value(summary.exceptionMemoryAppliedCount)],
    ['Score adjustment guardrails', value(summary.scoreAdjustmentGuardrailCount)],
    ['Exception trust-gate rejections', value(summary.exceptionRejectedByTrustGateCount)],
    ['Review queue before', value(summary.reviewQueueBefore)],
    ['Review queue after', value(summary.reviewQueueAfter)],
    ['Average risk before', formatScore(summary.averageRiskBeforeFeedback)],
    ['Average risk after', formatScore(summary.averageRiskAfterFeedback)],
  ];

  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div>
          <h2>Feedback Model</h2>
          <p>Simulated analyst feedback and JSON-based exception memory impact</p>
        </div>
        <span className="impact-pill">No live write-back</span>
      </div>
      <div className="metric-grid">
        {metrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>
      <div className="explain-panel">
        <h3>Interpretation</h3>
        <p>
          Feedback is simulated in the pipeline. The dashboard displays the resulting priority changes, but it does not
          write analyst decisions back to the JSON files.
        </p>
        <p>
          The dashboard includes interactive controls for simulated feedback input and detection record replay.
        </p>
      </div>
    </section>
  );
}
