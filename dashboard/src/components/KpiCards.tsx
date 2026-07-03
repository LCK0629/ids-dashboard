import type { FeedbackEvaluationSummary, FusionEvaluationSummary } from '../types/alerts';
import { formatPercent, formatScore } from '../utils/alertFilters';

interface KpiCardsProps {
  feedbackSummary: FeedbackEvaluationSummary;
  fusionSummary: FusionEvaluationSummary;
}

function metric(value: number | string | undefined | null): string {
  if (value === undefined || value === null || value === '') {
    return 'N/A';
  }
  return String(value);
}

export function KpiCards({ feedbackSummary, fusionSummary }: KpiCardsProps) {
  const cards = [
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
    <section className="kpi-grid" aria-label="Dashboard KPIs">
      {cards.map(([label, value]) => (
        <article className="kpi-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </article>
      ))}
    </section>
  );
}
