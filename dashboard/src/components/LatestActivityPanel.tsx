import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatScore } from '../utils/alertFilters';

interface LatestActivityPanelProps {
  alerts: FeedbackAdjustedAlert[];
  selectedAlertId?: string;
  isReplayMode: boolean;
  replayIndex: number;
  totalAlerts: number;
  onSelectAlert: (alert: FeedbackAdjustedAlert) => void;
}

export function LatestActivityPanel({
  alerts,
  selectedAlertId,
  isReplayMode,
  replayIndex,
  totalAlerts,
  onSelectAlert,
}: LatestActivityPanelProps) {
  const startIndex = Math.max(0, alerts.length - 8);
  const latestAlerts = alerts
    .slice(startIndex)
    .map((alert, index) => ({
      alert,
      sequence: startIndex + index + 1,
    }))
    .reverse();
  const replayText = isReplayMode
    ? `Replay ${Math.min(replayIndex, totalAlerts)} / ${totalAlerts}`
    : 'Ready for replay';

  return (
    <section className="panel latest-activity-panel">
      <div className="panel-header">
        <div>
          <h2>Latest Activity</h2>
          <p>Newest replayed alerts in arrival order, separate from risk priority</p>
        </div>
        <span className="status-pill muted">{replayText}</span>
      </div>
      <div className="latest-activity-list">
        {latestAlerts.length === 0 && (
          <div className="latest-empty">
            Start replay to see incoming alert activity.
          </div>
        )}
        {latestAlerts.map(({ alert, sequence }) => (
          <button
            className={`latest-activity-item${selectedAlertId === alert.id ? ' selected' : ''}`}
            key={`${sequence}-${alert.id}`}
            onClick={() => onSelectAlert(alert)}
            type="button"
          >
            <span className="sequence-badge">#{sequence}</span>
            <span className="latest-activity-main">
              <strong>{alert.id}</strong>
              <span>{alert.fusionAttackType || alert.signatureAttackType || 'Unknown'}</span>
            </span>
            <span className="latest-activity-meta">
              <b>{formatScore(alert.currentRiskScore)}</b>
              <small>{alert.localFeedbackLabel || alert.fusionDecision || 'No decision'}</small>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
