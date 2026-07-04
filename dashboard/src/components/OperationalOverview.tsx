import type { FeedbackAdjustedAlert, FeedbackEvaluationSummary } from '../types/alerts';
import { formatScore, isActionableAlert, isSuppressedOrResolved } from '../utils/alertFilters';

interface OperationalOverviewProps {
  alerts: FeedbackAdjustedAlert[];
  feedbackSummary: FeedbackEvaluationSummary;
}

function metric(value: number | undefined): string {
  return value === undefined ? 'N/A' : String(value);
}

function barWidth(value: number, max: number): string {
  if (!max) {
    return '0%';
  }
  return `${Math.min(100, Math.round((value / max) * 100))}%`;
}

export function OperationalOverview({ alerts, feedbackSummary }: OperationalOverviewProps) {
  const highRiskCount = alerts.filter((alert) => Number(alert.currentRiskScore ?? 0) >= 70).length;
  const adjustedCount = alerts.filter((alert) => alert.feedbackApplied).length;
  const activeAlertCount = alerts.filter(isActionableAlert).length;
  const suppressedCount = alerts.filter(isSuppressedOrResolved).length;
  const reviewReduction = Number(feedbackSummary.reviewQueueBefore ?? 0) - Number(feedbackSummary.reviewQueueAfter ?? 0);
  const maxCount = Math.max(alerts.length, 1);
  const rows = [
    ['Active alerts', activeAlertCount, 'Promoted for analyst attention'],
    ['High-risk records', highRiskCount, 'Current score >= 70'],
    ['Suppressed / resolved', suppressedCount, 'Low-risk or feedback-resolved records'],
    ['Adjusted records', adjustedCount, 'Feedback or exception memory affected the record'],
    ['After avg risk', Number(feedbackSummary.averageRiskAfterFeedback ?? 0), 'Stage 5 current score average'],
  ] as const;

  return (
    <section className="panel overview-panel">
      <div className="panel-header">
        <div>
          <h2>Operational Overview</h2>
          <p>Processed flow records retained for audit, with active alerts promoted for triage</p>
        </div>
        <span className="impact-pill">Review queue {reviewReduction >= 0 ? '-' : '+'}{Math.abs(reviewReduction)}</span>
      </div>
      <div className="overview-grid">
        {rows.map(([label, value, note]) => (
          <div className="overview-row" key={label}>
            <div>
              <strong>{label}</strong>
              <span>{note}</span>
            </div>
            <b>{label.includes('risk') ? formatScore(value) : metric(value)}</b>
            <div className="bar-track">
              <span style={{ width: barWidth(value, label.includes('risk') ? 100 : maxCount) }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
