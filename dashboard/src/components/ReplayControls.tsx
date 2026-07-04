import type { ReplaySpeed } from '../types/feedback';

interface ReplayControlsProps {
  isReplayMode: boolean;
  isReplayRunning: boolean;
  replaySpeed: ReplaySpeed;
  replayIndex: number;
  totalAlerts: number;
  onToggleReplayMode: () => void;
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onReset: () => void;
  onShowAll: () => void;
  onSpeedChange: (speed: ReplaySpeed) => void;
}

export function ReplayControls({
  isReplayMode,
  isReplayRunning,
  replaySpeed,
  replayIndex,
  totalAlerts,
  onToggleReplayMode,
  onStart,
  onPause,
  onResume,
  onReset,
  onShowAll,
  onSpeedChange,
}: ReplayControlsProps) {
  const complete = isReplayMode && replayIndex >= totalAlerts;
  const status = !isReplayMode
    ? 'All detection records visible'
    : complete
      ? 'Replay complete'
      : isReplayRunning
        ? 'Replay running'
        : 'Replay paused';

  return (
    <section className="panel replay-panel">
      <div className="panel-header">
        <div>
          <h2>Simulated Replay</h2>
          <p>Static JSON replay dataset · Not live packet capture · UI-only analyst feedback</p>
        </div>
        <span className="impact-pill">{status}</span>
      </div>
      <div className="replay-controls">
        <button type="button" onClick={onToggleReplayMode}>
          {isReplayMode ? 'Replay Mode On' : 'Replay Mode Off'}
        </button>
        <button type="button" onClick={onStart}>Start Replay</button>
        <button type="button" onClick={onPause} disabled={!isReplayRunning}>Pause Replay</button>
        <button type="button" onClick={onResume} disabled={!isReplayMode || isReplayRunning || complete}>Resume Replay</button>
        <button type="button" onClick={onReset}>Reset Replay</button>
        <button type="button" onClick={onShowAll}>Show All Records</button>
        <div className="speed-group" aria-label="Replay speed">
          {[1, 2, 5].map((speed) => (
            <button
              className={replaySpeed === speed ? 'active' : ''}
              key={speed}
              onClick={() => onSpeedChange(speed as ReplaySpeed)}
              type="button"
            >
              {speed}x
            </button>
          ))}
        </div>
        <strong>{Math.min(replayIndex, totalAlerts)} / {totalAlerts}</strong>
      </div>
    </section>
  );
}
