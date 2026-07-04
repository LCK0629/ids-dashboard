import type { FeedbackEvaluationSummary, FusionEvaluationSummary } from '../types/alerts';
import type { SessionKpis } from '../types/feedback';
import { formatPercent, formatScore } from '../utils/alertFilters';

interface KpiCardsProps {
  feedbackSummary: FeedbackEvaluationSummary;
  fusionSummary: FusionEvaluationSummary;
  sessionKpis: SessionKpis;
}

function metric(value: number | string | undefined | null): string {
  if (value === undefined || value === null || value === '') {
    return 'N/A';
  }
  return String(value);
}

export function KpiCards({ feedbackSummary, fusionSummary, sessionKpis }: KpiCardsProps) {
  const sessionCards = [
    ['Visible Records', metric(sessionKpis.visibleRecords)],
    ['All Detection Records', metric(sessionKpis.allDetectionRecords)],
    ['Active Alerts', metric(sessionKpis.activeAlerts)],
    ['Suppressed / Resolved', metric(sessionKpis.suppressedResolved)],
    ['Reviewed in session', metric(sessionKpis.reviewedInSession)],
    ['Local feedback applied', metric(sessionKpis.localFeedbackApplied)],
    ['Avg current risk', formatScore(sessionKpis.averageCurrentRisk)],
    ['High Risk Records', metric(sessionKpis.highRiskRecords)],
    ['Requires review', metric(sessionKpis.requiresReview)],
    ['Replay progress', sessionKpis.replayProgress],
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
    ['Stage 4 ID overlap', formatPercent(fusionSummary.idAlignmentSummary?.overlapRateAgainstStage2)],
  ];

  return (
    <section className="kpi-section" aria-label="Dashboard KPIs">
      <div className="kpi-title">
        <strong>Current View Metrics</strong>
        <span>Recalculated from visible detection records, active alert criteria, and local feedback</span>
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
        <strong>Stage 5 Pipeline Metrics</strong>
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
