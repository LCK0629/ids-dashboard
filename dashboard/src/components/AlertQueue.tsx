import type { FeedbackAdjustedAlert } from '../types/alerts';
import {
  formatScore,
  isAdjusted,
  isHighRisk,
  recordStatusBadges,
  requiresReview,
} from '../utils/alertFilters';

interface AlertQueueProps {
  alerts: FeedbackAdjustedAlert[];
  title: string;
  totalDetectionRecords: number;
  selectedAlertId?: string;
  onSelectAlert: (alert: FeedbackAdjustedAlert) => void;
}

function classNameForAlert(alert: FeedbackAdjustedAlert, selected: boolean): string {
  const classes = ['alert-row'];
  if (selected) classes.push('selected');
  if (isHighRisk(alert)) classes.push('high-risk');
  if (isAdjusted(alert)) classes.push('adjusted');
  if (requiresReview(alert)) classes.push('review');
  if (alert.localGuardrailMessage || Boolean(alert.feedbackGuardrailsApplied?.length)) classes.push('guardrail');
  return classes.join(' ');
}

export function AlertQueue({
  alerts,
  title,
  totalDetectionRecords,
  selectedAlertId,
  onSelectAlert,
}: AlertQueueProps) {
  return (
    <section className="panel queue-panel">
      <div className="panel-header">
        <div>
          <h2>{title}</h2>
          <p>Click a detection record to inspect fusion, ML, signature, and feedback evidence</p>
        </div>
        <span>Showing {alerts.length} of {totalDetectionRecords} detection records</span>
      </div>
      <div className="table-wrap">
        <table className="alert-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Current risk</th>
              <th>Fusion risk</th>
              <th>Attack type</th>
              <th>Decision</th>
              <th>Review</th>
              <th>Local feedback</th>
              <th>Record status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => {
              const badges = recordStatusBadges(alert);
              return (
                <tr
                  className={classNameForAlert(alert, selectedAlertId === alert.id)}
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                >
                  <td><strong>{alert.id}</strong></td>
                  <td><span className="risk-badge">{formatScore(alert.currentRiskScore)}</span></td>
                  <td>{formatScore(alert.fusionRiskScore)}</td>
                  <td className="attack-type">{alert.fusionAttackType || 'Unknown'}</td>
                  <td>{alert.fusionDecision || 'No decision'}</td>
                  <td>{alert.requiresAnalystReview ? 'Review' : 'No review'}</td>
                  <td>{alert.localFeedbackLabel ? <span className="local-badge">{alert.localFeedbackLabel}</span> : 'None'}</td>
                  <td>
                    <div className="status-badge-list">
                      {badges.length
                        ? badges.map((badge) => <span className="record-badge" key={badge}>{badge}</span>)
                        : <span>{alert.analystFeedbackStatus || 'Active'}</span>}
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
