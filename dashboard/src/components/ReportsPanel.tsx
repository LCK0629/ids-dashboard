import type { FeedbackEvaluationSummary, FusionEvaluationSummary } from '../types/alerts';
import { formatPercent, formatScore } from '../utils/alertFilters';

interface ReportsPanelProps {
  feedbackSummary: FeedbackEvaluationSummary;
  fusionSummary: FusionEvaluationSummary;
}

function value(input: number | string | undefined): string {
  if (input === undefined || input === null || input === '') {
    return 'N/A';
  }
  return String(input);
}

export function ReportsPanel({ feedbackSummary, fusionSummary }: ReportsPanelProps) {
  const groundTruth = fusionSummary.groundTruthEvaluation;
  const binary = groundTruth?.binaryDetectionMetrics;
  const risk = groundTruth?.riskPrioritisationMetrics;
  const review = groundTruth?.analystReviewMetrics;
  const metrics = [
    ['Fusion accuracy', formatPercent(groundTruth?.simpleFusionAccuracy)],
    ['Binary precision', formatPercent(binary?.precision)],
    ['Binary recall', formatPercent(binary?.recall)],
    ['Binary F1', formatPercent(binary?.f1)],
    ['Top-50 precision', formatPercent(risk?.top50Precision)],
    ['Top-100 precision', formatPercent(risk?.top100Precision)],
    ['Top-200 precision', formatPercent(risk?.top200Precision)],
    ['High-risk precision', formatPercent(risk?.highRiskThresholdPrecision)],
    ['Review precision', formatPercent(review?.reviewPrecision)],
    ['Review rate', formatPercent(review?.reviewRate)],
    ['ID alignment status', value(fusionSummary.idAlignmentSummary?.alignmentStatus)],
    ['Average risk after feedback', formatScore(feedbackSummary.averageRiskAfterFeedback)],
  ];

  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div>
          <h2>Reports</h2>
          <p>Prototype evaluation numbers joined only after detection and feedback adjustment</p>
        </div>
        <span className="impact-pill">Prototype metrics</span>
      </div>
      <div className="metric-grid">
        {metrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>
    </section>
  );
}
