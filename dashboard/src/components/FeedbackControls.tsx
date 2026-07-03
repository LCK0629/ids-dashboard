import type { AnalystFeedbackAction } from '../types/feedback';

interface FeedbackControlsProps {
  disabled?: boolean;
  activeAction?: string;
  onApplyFeedback: (action: AnalystFeedbackAction) => void;
  onResetFeedback: () => void;
}

const actions: Array<{ action: AnalystFeedbackAction; label: string }> = [
  { action: 'CONFIRMED_THREAT', label: 'Confirm Threat' },
  { action: 'FALSE_POSITIVE', label: 'Mark False Positive' },
  { action: 'EXPECTED_ACTIVITY', label: 'Expected Activity' },
  { action: 'NEEDS_INVESTIGATION', label: 'Needs Investigation' },
  { action: 'ESCALATED', label: 'Escalate' },
];

export function FeedbackControls({
  disabled,
  activeAction,
  onApplyFeedback,
  onResetFeedback,
}: FeedbackControlsProps) {
  return (
    <section className="feedback-controls" aria-label="UI-only analyst feedback controls">
      <div className="feedback-control-header">
        <strong>UI-only analyst feedback</strong>
        <span>No backend write-back</span>
      </div>
      <div className="feedback-buttons">
        {actions.map((item) => (
          <button
            className={activeAction === item.action ? 'active' : ''}
            disabled={disabled}
            key={item.action}
            onClick={() => onApplyFeedback(item.action)}
            type="button"
          >
            {item.label}
          </button>
        ))}
        <button disabled={disabled || !activeAction} onClick={onResetFeedback} type="button">
          Reset Feedback
        </button>
      </div>
    </section>
  );
}
