import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatScore, isAdjusted, isHighRisk, requiresReview } from '../utils/alertFilters';

interface AlertQueueProps {
  alerts: FeedbackAdjustedAlert[];
  selectedAlertId?: string;
  onSelectAlert: (alert: FeedbackAdjustedAlert) => void;
}

function classNameForAlert(alert: FeedbackAdjustedAlert, selected: boolean): string {
  const classes = ['alert-row'];
  if (selected) classes.push('selected');
  if (isHighRisk(alert)) classes.push('high-risk');
  if (isAdjusted(alert)) classes.push('adjusted');
  if (requiresReview(alert)) classes.push('review');
  return classes.join(' ');
}

export function AlertQueue({ alerts, selectedAlertId, onSelectAlert }: AlertQueueProps) {
  return (
    <section className="panel queue-panel">
      <div className="panel-header">
        <div>
          <h2>Alert Queue</h2>
          <p>Click an alert to inspect fusion, ML, signature, and feedback evidence</p>
        </div>
        <span>{alerts.length} alerts</span>
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
              <th>Feedback status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
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
                <td>{alert.analystFeedbackStatus || 'unknown'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
