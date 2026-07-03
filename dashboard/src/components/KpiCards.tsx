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
    ['Visible alerts', metric(sessionKpis.visibleAlerts)],
    ['Reviewed in session', metric(sessionKpis.reviewedInSession)],
    ['Local feedback applied', metric(sessionKpis.localFeedbackApplied)],
    ['Avg current risk', formatScore(sessionKpis.averageCurrentRisk)],
    ['High risk alerts', metric(sessionKpis.highRiskAlerts)],
    ['Requires review', metric(sessionKpis.requiresReview)],
    ['False positives marked', metric(sessionKpis.falsePositivesMarked)],
    ['Escalated alerts', metric(sessionKpis.escalatedAlerts)],
    ['Replay progress', sessionKpis.replayProgress],
  ];
  const pipelineCards = [
    ['Total alerts', metric(feedbackSummary.totalAlerts)],
    ['Alerts adjusted', metric(feedbackSummary.alertsAdjusted)],
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
        <strong>Current dashboard session metrics</strong>
        <span>Recalculated from replay-visible alerts and local feedback</span>
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
        <strong>Stage 5 pipeline metrics</strong>
        <span>Static JSON summary from generated Stage 5 output</span>
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
