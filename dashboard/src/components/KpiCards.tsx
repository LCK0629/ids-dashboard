import type { FeedbackEvaluationSummary, FlowAlertCounts, FusionEvaluationSummary } from '../types/alerts';
import type { SessionKpis } from '../types/feedback';
import { formatPercent, formatScore } from '../utils/alertFilters';

interface KpiCardsProps {
  feedbackSummary: FeedbackEvaluationSummary;
  flowAlertCounts: FlowAlertCounts;
  fusionSummary: FusionEvaluationSummary;
  sessionKpis: SessionKpis;
}

function metric(value: number | string | undefined | null): string {
  if (value === undefined || value === null || value === '') {
    return 'N/A';
  }
  return String(value);
}

export function KpiCards({
  feedbackSummary,
  flowAlertCounts,
  fusionSummary,
  sessionKpis,
}: KpiCardsProps) {
  const sessionCards = [
    ['Total Processed Flows', metric(flowAlertCounts.totalProcessedFlows)],
    ['All Detection Records', metric(flowAlertCounts.allDetectionRecords)],
    ['Active Alerts', metric(flowAlertCounts.activeAlerts)],
    ['Requires Review', metric(flowAlertCounts.reviewRequiredAlerts)],
    ['Suppressed / Resolved', metric(flowAlertCounts.suppressedOrResolvedRecords)],
    ['High Risk Records', metric(flowAlertCounts.highRiskRecords)],
    ['Average Current Risk', formatScore(sessionKpis.averageCurrentRisk)],
    ['Feedback Adjusted', metric(flowAlertCounts.feedbackAdjustedRecords)],
    ['Visible Records', metric(sessionKpis.visibleRecords)],
    ['Replay Progress', sessionKpis.replayProgress],
  ];
  const pipelineCards = [
    ['Total Processed Flows', metric(feedbackSummary.totalAlerts)],
    ['Feedback Adjusted', metric(feedbackSummary.alertsAdjusted)],
    ['Review before', metric(feedbackSummary.reviewQueueBefore)],
    ['Review after', metric(feedbackSummary.reviewQueueAfter)],
    ['Avg risk before', formatScore(feedbackSummary.averageRiskBeforeFeedback)],
    ['Avg risk after', formatScore(feedbackSummary.averageRiskAfterFeedback)],
    ['Score guardrails', metric(feedbackSummary.scoreAdjustmentGuardrailCount)],
    ['Exception trust gates', metric(feedbackSummary.exceptionRejectedByTrustGateCount)],
    ['Prediction ID overlap', formatPercent(fusionSummary.idAlignmentSummary?.overlapRateAgainstStage2)],
  ];

  return (
    <section className="kpi-section" aria-label="Dashboard KPIs">
      <div className="kpi-title">
        <strong>Flow vs Alert Metrics</strong>
        <span>Dataset-level counts plus the current visible detection records</span>
      </div>
      <div className="kpi-grid">
        {sessionCards.map(([label, value]) => (
          <article className="kpi-card" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>
      <div className="kpi-title secondary">
        <strong>Pipeline Metrics</strong>
        <span>Static JSON summary for processed flow records retained for audit and evaluation</span>
      </div>
      <div className="kpi-grid pipeline">
        {pipelineCards.map(([label, value]) => (
          <article className="kpi-card" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>
    </section>
  );
}
