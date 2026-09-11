import type { AnalystAlertV1 } from '../types/dashboardData';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';
import { analystRecommendation, buildFeatureInterpretation } from '../utils/investigation';
import { AutomatedDetectionEvidence } from './automated-evidence/AutomatedDetectionEvidence';
import { HitlAdaptationEvidence } from './hitl-adaptation/HitlAdaptationEvidence';
import { FeatureSummaryPanel } from './FeatureSummaryPanel';
import { FeedbackControls } from './FeedbackControls';
import { FeedbackImpactPanel } from './FeedbackImpactPanel';
import { ScoreComparison } from './ScoreComparison';

interface InvestigationsPanelProps {
  alert?: FeedbackAdjustedAlert;
  analystAlert?: AnalystAlertV1;
  onApplyFeedback?: (alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) => void;
  onClearSessionPreview?: (alert: FeedbackAdjustedAlert) => void;
  sessionNote?: string;
  onSessionNoteChange?: (alert: FeedbackAdjustedAlert, note: string) => void;
}

export function InvestigationsPanel({
  alert,
  analystAlert,
  onApplyFeedback,
  onClearSessionPreview,
  sessionNote = '',
  onSessionNoteChange,
}: InvestigationsPanelProps) {
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

      <div className="investigation-section hitl-investigation-section">
        <HitlAdaptationEvidence alert={analystAlert} density="expanded" />
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

      <div className="investigation-section feedback-decision-section">
        <h3>Session Preview</h3>
        <p className="helper-text">
          This temporary browser action is not persisted and has not yet become historical feedback for future alerts. It does not write to JSON or retrain the model.
        </p>
        <FeedbackControls
          activeAction={alert.localFeedbackAction}
          disabled={!onApplyFeedback || !onClearSessionPreview || !onSessionNoteChange}
          onApplyFeedback={(action) => onApplyFeedback?.(alert, action)}
          onClearSessionPreview={() => onClearSessionPreview?.(alert)}
          onSessionNoteChange={(note) => onSessionNoteChange?.(alert, note)}
          sessionNote={sessionNote}
        />
        <FeedbackImpactPanel alert={alert} sessionNote={sessionNote} />
      </div>

      <div className="explain-panel">
        <h3>Analyst Recommendation</h3>
        <p>{recommendation}</p>
      </div>
    </section>
  );
}
