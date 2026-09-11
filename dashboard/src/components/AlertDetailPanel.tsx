import type { AnalystAlertV1 } from '../types/dashboardData';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystFeedbackAction } from '../types/feedback';
import { AutomatedDetectionEvidence } from './automated-evidence/AutomatedDetectionEvidence';
import { HitlAdaptationEvidence } from './hitl-adaptation/HitlAdaptationEvidence';
import { FeedbackControls } from './FeedbackControls';
import { FeedbackImpactPanel } from './FeedbackImpactPanel';
import { ScoreComparison } from './ScoreComparison';

interface AlertDetailPanelProps {
  alert?: FeedbackAdjustedAlert;
  analystAlert?: AnalystAlertV1;
  onApplyFeedback?: (alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) => void;
  onResetFeedback?: (alert: FeedbackAdjustedAlert) => void;
}

function value(input: unknown): string {
  if (input === undefined || input === null || input === '') return 'N/A';
  if (typeof input === 'boolean') return input ? 'Yes' : 'No';
  return String(input);
}

export function AlertDetailPanel({ alert, analystAlert, onApplyFeedback, onResetFeedback }: AlertDetailPanelProps) {
  if (!alert || !analystAlert) {
    return (
      <aside className="panel detail-panel empty">
        <h2>Detection Record Detail</h2>
        <p>Select a detection record to inspect its automated evidence and feedback state.</p>
      </aside>
    );
  }

  return (
    <aside className="panel detail-panel">
      <div className="panel-header">
        <h2>{analystAlert.identity.id}</h2>
        <span>{analystAlert.automatedDetection.attackType}</span>
      </div>

      <ScoreComparison alert={alert} />
      <AutomatedDetectionEvidence alert={analystAlert} density="compact" />
      <HitlAdaptationEvidence alert={analystAlert} density="compact" />

      <FeedbackControls
        activeAction={alert.localFeedbackAction}
        disabled={!onApplyFeedback || !onResetFeedback}
        onApplyFeedback={(action) => onApplyFeedback?.(alert, action)}
        onResetFeedback={() => onResetFeedback?.(alert)}
      />

      <section className="evidence-block">
        <h3>Session Preview</h3>
        <p className="helper-text">This temporary browser action is not persisted and has not yet become historical feedback for future alerts.</p>
        <FeedbackImpactPanel alert={alert} />
      </section>

      <section className="evidence-block">
        <h3>Feedback Evidence</h3>
        <div className="detail-grid">
          <div className="detail-item"><span>Feedback applied</span><strong>{value(alert.feedbackApplied)}</strong></div>
          <div className="detail-item"><span>Adjustment</span><strong>{value(alert.feedbackAdjustment)}</strong></div>
          <div className="detail-item"><span>Matched feedback</span><strong>{value(alert.matchedFeedbackId)}</strong></div>
          <div className="detail-item"><span>Feedback status</span><strong>{value(alert.analystFeedbackStatus)}</strong></div>
          <div className="detail-item"><span>Local feedback</span><strong>{value(alert.localFeedbackLabel)}</strong></div>
        </div>
        <p>{alert.feedbackReason || 'No feedback reason recorded.'}</p>
        {alert.localFeedbackReason && <p>{alert.localFeedbackReason}</p>}
        {alert.localGuardrailMessage && <p className="guardrail-message">{alert.localGuardrailMessage}</p>}
      </section>
    </aside>
  );
}
