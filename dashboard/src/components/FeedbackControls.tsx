import type { AnalystFeedbackAction } from '../types/feedback';
import {
  LEARNING_FEEDBACK_ACTIONS,
  normalizeSessionNote,
  SESSION_NOTE_MAX_LENGTH,
  SESSION_PREVIEW_ACTION_POLICY,
  WORKFLOW_ACTIONS,
} from '../utils/sessionPreview.js';

interface FeedbackControlsProps {
  disabled?: boolean;
  activeAction?: string;
  onApplyFeedback: (action: AnalystFeedbackAction) => void;
  onClearSessionPreview: () => void;
  sessionNote: string;
  onSessionNoteChange: (note: string) => void;
}

function ActionGroup({
  actions,
  activeAction,
  disabled,
  label,
  description,
  onApplyFeedback,
}: {
  actions: readonly AnalystFeedbackAction[];
  activeAction?: string;
  disabled?: boolean;
  label: string;
  description: string;
  onApplyFeedback: (action: AnalystFeedbackAction) => void;
}) {
  return (
    <fieldset className="feedback-action-group" disabled={disabled}>
      <legend>{label}</legend>
      <p>{description}</p>
      <div className="feedback-buttons">
        {actions.map((action) => {
          const policy = SESSION_PREVIEW_ACTION_POLICY[action];
          return (
            <button
              aria-pressed={activeAction === action}
              className={activeAction === action ? 'active' : ''}
              key={action}
              onClick={() => onApplyFeedback(action)}
              type="button"
            >
              {policy.label}
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}

export function FeedbackControls({
  disabled,
  activeAction,
  onApplyFeedback,
  onClearSessionPreview,
  sessionNote,
  onSessionNoteChange,
}: FeedbackControlsProps) {
  return (
    <section className="feedback-controls" aria-label="Session-only analyst feedback and workflow controls">
      <div className="feedback-control-header">
        <div>
          <strong>Session-only analyst actions</strong>
          <p>Browser preview only. No backend write-back or historical-memory update.</p>
        </div>
        <span>Not persisted</span>
      </div>
      <div className="feedback-action-groups">
        <ActionGroup
          actions={LEARNING_FEEDBACK_ACTIONS}
          activeAction={activeAction}
          description="May become historical evidence for similar future alerts only after persistence is implemented."
          disabled={disabled}
          label="Learning Feedback"
          onApplyFeedback={onApplyFeedback}
        />
        <ActionGroup
          actions={WORKFLOW_ACTIONS}
          activeAction={activeAction}
          description="Describes investigation handling; it does not teach future malicious or benign outcomes."
          disabled={disabled}
          label="Workflow Actions"
          onApplyFeedback={onApplyFeedback}
        />
      </div>
      <label className="session-note-field">
        <span>Session-only analyst note</span>
        <textarea
          disabled={disabled}
          maxLength={SESSION_NOTE_MAX_LENGTH}
          onBlur={(event) => onSessionNoteChange(normalizeSessionNote(event.target.value))}
          onChange={(event) => onSessionNoteChange(event.target.value.slice(0, SESSION_NOTE_MAX_LENGTH))}
          placeholder="Record investigation rationale for this browser session"
          rows={3}
          value={sessionNote}
        />
        <small>{sessionNote.length} / {SESSION_NOTE_MAX_LENGTH} characters · no scoring or similarity influence</small>
      </label>
      <div className="session-preview-clear">
        <button disabled={disabled || !activeAction} onClick={onClearSessionPreview} type="button">
          Clear Session Preview
        </button>
        <span>This removes only the temporary browser preview. It does not delete historical feedback.</span>
      </div>
    </section>
  );
}
