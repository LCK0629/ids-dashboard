import type { AnalystAlertV1 } from '../types/dashboardData';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';
import { formatScore } from '../utils/alertFilters';
import { analystRecommendation, buildFeatureInterpretation } from '../utils/investigation';
import { AutomatedDetectionEvidence } from './automated-evidence/AutomatedDetectionEvidence';
import { FeatureSummaryPanel } from './FeatureSummaryPanel';
import { FeedbackControls } from './FeedbackControls';
import { FeedbackImpactPanel } from './FeedbackImpactPanel';
import { ScoreComparison } from './ScoreComparison';

interface InvestigationsPanelProps {
  alert?: FeedbackAdjustedAlert;
  analystAlert?: AnalystAlertV1;
  onApplyFeedback?: (alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) => void;
  onResetFeedback?: (alert: FeedbackAdjustedAlert) => void;
}

export function InvestigationsPanel({ alert, analystAlert, onApplyFeedback, onResetFeedback }: InvestigationsPanelProps) {
  if (!alert || !analystAlert) {
    return (
      <section className="panel full-panel">
        <div className="panel-header">
          <h2>Investigations</h2>
          <span>No detection record selected</span>
        </div>
      </section>
    );
  }

  const interpretations = buildFeatureInterpretation(alert);
  const recommendation = analystRecommendation(alert);

  return (
    <section className="panel full-panel investigation-panel">
      <div className="panel-header">
        <div>
          <h2>Investigation Case</h2>
          <p>{analystAlert.identity.id} · {analystAlert.automatedDetection.attackType}</p>
        </div>
        <span className="impact-pill">{alert.requiresAnalystReview ? 'Review required' : 'No review required'}</span>
      </div>

      <ScoreComparison alert={alert} />

      <div className="investigation-section">
        <h3>Feature Summary</h3>
        <p className="helper-text">Observable flow-level context only. Missing values are shown as N/A.</p>
        <FeatureSummaryPanel alert={alert} />
      </div>

      <div className="investigation-section automated-investigation-section">
        <AutomatedDetectionEvidence alert={analystAlert} density="expanded" />
      </div>

      <div className="investigation-section">
        <h3>General Investigation Context</h3>
        <p className="helper-text">
          General domain context only; not model attribution. TreeSHAP above shows the feature-level model explanation for this prediction.
        </p>
        <div className="insight-list">
          {interpretations.map((item) => <p key={item}>{item}</p>)}
        </div>
      </div>

      <div className="explain-panel">
        <h3>Current Feedback Context</h3>
        <p>{alert.feedbackReason || 'No pipeline feedback reason recorded.'}</p>
        <p className="helper-text">
          Detection Score remains {formatScore(alert.detectionScore)}. Operational Priority is {formatScore(alert.operationalPriorityScore)}.
          Detailed historical adaptation causality is reserved for the next dashboard increment.
        </p>
      </div>

      <div className="investigation-section feedback-decision-section">
        <h3>Analyst Feedback Decision</h3>
        <p className="helper-text">
          Feedback submitted here is session-only and previews dashboard priority. It does not write to JSON or retrain the model.
        </p>
        <FeedbackControls
          activeAction={alert.localFeedbackAction}
          disabled={!onApplyFeedback || !onResetFeedback}
          onApplyFeedback={(action) => onApplyFeedback?.(alert, action)}
          onResetFeedback={() => onResetFeedback?.(alert)}
        />
        <FeedbackImpactPanel alert={alert} />
      </div>

      <div className="explain-panel">
        <h3>Analyst Recommendation</h3>
        <p>{recommendation}</p>
      </div>
    </section>
  );
}
