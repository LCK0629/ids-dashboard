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
    <section className="panel alert-queue">
      <div className="panel-header">
        <h2>Alert Queue</h2>
        <span>{alerts.length} alerts</span>
      </div>
      <div className="queue-list">
        {alerts.map((alert) => (
          <button
            className={classNameForAlert(alert, selectedAlertId === alert.id)}
            key={alert.id}
            onClick={() => onSelectAlert(alert)}
            type="button"
          >
            <div className="row-main">
              <strong>{alert.id}</strong>
              <span className="attack-type">{alert.fusionAttackType || 'Unknown'}</span>
              <span className="risk-badge">{formatScore(alert.currentRiskScore)}</span>
            </div>
            <div className="row-meta">
              <span>Fusion {formatScore(alert.fusionRiskScore)}</span>
              <span>{alert.fusionDecision || 'No decision'}</span>
              <span>{alert.requiresAnalystReview ? 'Review' : 'No review'}</span>
              <span>{alert.feedbackApplied ? 'Adjusted' : 'Unchanged'}</span>
              <span>{alert.analystFeedbackStatus || 'unknown'}</span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}
