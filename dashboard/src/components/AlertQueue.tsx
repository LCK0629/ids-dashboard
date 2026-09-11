import type { AnalystAlertV1 } from '../types/dashboardData';
import type { FeedbackAdjustedAlert } from '../types/alerts';
import { getDetectorStatePresentation } from '../utils/automatedEvidence.js';
import {
  getHistoricalAdjustmentPresentation,
  getReviewWorkflowPresentation,
} from '../utils/analystWorkflow.js';
import {
  formatScore,
  isAdjusted,
  isHighRisk,
  isScoreGuardrailApplied,
  recordStatusBadges,
  requiresReview,
} from '../utils/alertFilters';

interface AlertQueueProps {
  alerts: FeedbackAdjustedAlert[];
  title: string;
  totalDetectionRecords: number;
  analystAlertsById: Map<string, AnalystAlertV1>;
  selectedAlertId?: string;
  onSelectAlert: (alert: FeedbackAdjustedAlert) => void;
}

function classNameForAlert(alert: FeedbackAdjustedAlert, selected: boolean): string {
  const classes = ['alert-row'];
  if (selected) classes.push('selected');
  if (isHighRisk(alert)) classes.push('high-risk');
  if (isAdjusted(alert)) classes.push('adjusted');
  if (requiresReview(alert)) classes.push('review');
  if (isScoreGuardrailApplied(alert)) classes.push('guardrail');
  return classes.join(' ');
}

export function AlertQueue({
  alerts,
  title,
  totalDetectionRecords,
  analystAlertsById,
  selectedAlertId,
  onSelectAlert,
}: AlertQueueProps) {
  return (
    <section className="panel queue-panel">
      <div className="panel-header">
        <div>
          <h2>{title}</h2>
          <p>Select a record to inspect automated evidence, HITL adaptation, and analyst actions</p>
        </div>
        <span>Showing {alerts.length} of {totalDetectionRecords} detection records</span>
      </div>
      <div className="table-wrap">
        <table className="alert-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Operational Priority</th>
              <th>Detection Score</th>
              <th>Attack type</th>
              <th>Detector State</th>
              <th>HITL / Priority</th>
              <th>Review / Workflow</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr className="queue-empty-row">
                <td colSpan={7}>No detection records match the current filters.</td>
              </tr>
            )}
            {alerts.map((alert) => {
              const badges = recordStatusBadges(alert);
              const analystAlert = analystAlertsById.get(alert.id);
              const detectorState = analystAlert
                ? getDetectorStatePresentation(analystAlert)
                : { key: 'missing', label: 'Evidence unavailable', tone: 'warning' };
              const hitlState = analystAlert
                ? getHistoricalAdjustmentPresentation(analystAlert.adaptation)
                : { key: 'unavailable', label: 'HITL state unavailable', tone: 'muted' };
              const workflowState = getReviewWorkflowPresentation(alert, analystAlert);
              return (
                <tr
                  aria-label={`Open alert ${alert.id}`}
                  aria-selected={selectedAlertId === alert.id}
                  className={classNameForAlert(alert, selectedAlertId === alert.id)}
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelectAlert(alert);
                    }
                  }}
                  tabIndex={0}
                >
                  <td data-label="Alert ID"><strong>{alert.id}</strong></td>
                  <td data-label="Operational Priority">
                    <span className="risk-badge">{formatScore(alert.operationalPriorityScore)}</span>
                    {alert.sessionPreviewPriorityScore !== undefined && (
                      <small className="queue-session-preview">
                        Session preview {formatScore(alert.sessionPreviewPriorityScore)}
                      </small>
                    )}
                  </td>
                  <td data-label="Detection Score"><span className="secondary-score">{formatScore(alert.detectionScore)}</span></td>
                  <td className="attack-type" data-label="Attack Type">{alert.fusionAttackType || 'Unknown'}</td>
                  <td data-label="Detector State">
                    <span className={`queue-state ${detectorState.tone}`}>{detectorState.label}</span>
                  </td>
                  <td data-label="HITL / Priority">
                    <div className="queue-state-stack">
                      <span className={`queue-state ${hitlState.tone}`}>{hitlState.label}</span>
                      {alert.localFeedbackLabel && (
                        <span className="local-badge">Session: {alert.localFeedbackLabel}</span>
                      )}
                    </div>
                  </td>
                  <td data-label="Review / Workflow">
                    <div className="queue-state-stack">
                      <span className={`queue-state ${workflowState.tone}`}>{workflowState.label}</span>
                      {badges.map((badge) => <span className="record-badge" key={badge}>{badge}</span>)}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
