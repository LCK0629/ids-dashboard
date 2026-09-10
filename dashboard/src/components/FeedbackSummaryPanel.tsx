import type { FeedbackEvaluationSummary } from '../types/alerts';
import type { SessionKpis } from '../types/feedback';
import { formatScore } from '../utils/alertFilters';

interface FeedbackSummaryPanelProps {
  summary: FeedbackEvaluationSummary;
  sessionKpis: SessionKpis;
}

function value(input: number | undefined): string {
  return input === undefined ? 'N/A' : String(input);
}

export function FeedbackSummaryPanel({ summary, sessionKpis }: FeedbackSummaryPanelProps) {
  const pipelineMetrics = [
    ['Records adjusted', value(summary.alertsAdjusted)],
    ['Direct feedback count', value(summary.directFeedbackAppliedCount)],
    ['Exception memory applied', value(summary.exceptionMemoryAppliedCount)],
    ['Score adjustment guardrails', value(summary.scoreAdjustmentGuardrailCount)],
    ['Exception trust-gate rejections', value(summary.exceptionRejectedByTrustGateCount)],
    ['Review queue before', value(summary.reviewQueueBefore)],
    ['Review queue after', value(summary.reviewQueueAfter)],
    ['Average Detection Score', formatScore(summary.averageRiskBeforeFeedback)],
    ['Average Operational Priority', formatScore(summary.averageRiskAfterFeedback)],
  ];
  const sessionMetrics = [
    ['Local feedback applied', value(sessionKpis.localFeedbackApplied)],
    ['Confirmed threats', value(sessionKpis.confirmedThreats)],
    ['False positives marked', value(sessionKpis.falsePositivesMarked)],
    ['Expected activity marked', value(sessionKpis.expectedActivityMarked)],
    ['Needs investigation', value(sessionKpis.needsInvestigation)],
    ['Escalated alerts', value(sessionKpis.escalatedAlerts)],
    ['Average priority change', formatScore(sessionKpis.averageRiskChange)],
    ['Guardrails triggered', value(sessionKpis.guardrailsTriggered)],
  ];

  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div>
          <h2>Feedback Model</h2>
          <p>Frozen calibration feedback and held-out priority evaluation</p>
        </div>
        <span className="impact-pill">No live write-back</span>
      </div>
      <div className="explain-panel">
        <h3>Human Feedback Loop</h3>
        <p>
          Analyst feedback can raise or lower local priority, update review status, reorder the active queue, and update
          the current session metrics. Guardrails prevent unsafe suppression of critical, Infiltration, or conflicting-evidence records.
        </p>
        <p>
          UI-only analyst feedback. No backend write-back. No JSON files are modified. No model retraining is performed.
        </p>
      </div>
      <div className="kpi-title feedback-panel-title">
        <strong>Pipeline Feedback Summary</strong>
        <span>Formal held-out pipeline summary; manual exception memory is disabled</span>
      </div>
      <div className="metric-grid">
        {pipelineMetrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>
      <div className="kpi-title feedback-panel-title">
        <strong>Current Session Feedback Summary</strong>
        <span>Interactive local feedback applied only inside this browser session</span>
      </div>
      <div className="metric-grid">
        {sessionMetrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>
      <div className="explain-panel">
        <h3>Interpretation</h3>
        <p>
          The formal artifact uses frozen calibration feedback and keeps held-out records isolated during ranking. The
          dashboard also provides a separate UI-only preview so an analyst can explore priority changes in this session.
        </p>
        <p>
          The dashboard includes interactive controls for simulated feedback input and detection record replay.
        </p>
      </div>
    </section>
  );
}
