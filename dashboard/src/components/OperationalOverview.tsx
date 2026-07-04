import type { FeedbackAdjustedAlert, FeedbackEvaluationSummary, FlowAlertCounts } from '../types/alerts';
import { formatScore } from '../utils/alertFilters';

interface OperationalOverviewProps {
  alerts: FeedbackAdjustedAlert[];
  feedbackSummary: FeedbackEvaluationSummary;
  flowAlertCounts: FlowAlertCounts;
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

export function OperationalOverview({ alerts, feedbackSummary, flowAlertCounts }: OperationalOverviewProps) {
  const reviewReduction = Number(feedbackSummary.reviewQueueBefore ?? 0) - Number(feedbackSummary.reviewQueueAfter ?? 0);
  const maxCount = Math.max(flowAlertCounts.totalProcessedFlows, alerts.length, 1);
  const rows = [
    ['Processed flows', flowAlertCounts.totalProcessedFlows, 'Flow Processing'],
    ['Detection records', flowAlertCounts.allDetectionRecords, 'Flow Processing'],
    ['Active alerts', flowAlertCounts.activeAlerts, 'Alert Promotion'],
    ['Requires review', flowAlertCounts.reviewRequiredAlerts, 'Alert Promotion'],
    ['High-risk records', flowAlertCounts.highRiskRecords, 'Alert Promotion'],
    ['Suppressed / resolved', flowAlertCounts.suppressedOrResolvedRecords, 'Suppression / Feedback'],
    ['Feedback adjusted', flowAlertCounts.feedbackAdjustedRecords, 'Suppression / Feedback'],
    ['Guardrail-limited', flowAlertCounts.guardrailLimitedRecords, 'Suppression / Feedback'],
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
      <div className="overview-grid breakdown">
        {rows.map(([label, value, note]) => (
          <div className="overview-row" key={label}>
            <div>
              <strong>{label}</strong>
              <span>{note}</span>
            </div>
            <b>{label === 'After avg risk' ? formatScore(value) : metric(value)}</b>
            <div className="bar-track">
              <span style={{ width: barWidth(value, label === 'After avg risk' ? 100 : maxCount) }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
