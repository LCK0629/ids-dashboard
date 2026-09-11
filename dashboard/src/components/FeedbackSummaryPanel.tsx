import { useState } from 'react';
import type { FeedbackEvaluationSummary } from '../types/alerts';
import type { SessionKpis } from '../types/feedback';
import type { DemoArtifactV1 } from '../types/dashboardData';
import { formatScore } from '../utils/alertFilters';
import { AutomatedDetectionEvidence } from './automated-evidence/AutomatedDetectionEvidence';
import { HitlAdaptationEvidence } from './hitl-adaptation/HitlAdaptationEvidence';

interface FeedbackSummaryPanelProps {
  summary: FeedbackEvaluationSummary;
  sessionKpis: SessionKpis;
  demoArtifact?: DemoArtifactV1 | null;
  demoErrors?: string[];
}

function value(input: number | undefined): string {
  return input === undefined ? 'N/A' : String(input);
}

export function FeedbackSummaryPanel({ summary, sessionKpis, demoArtifact, demoErrors = [] }: FeedbackSummaryPanelProps) {
  const [selectedScenarioId, setSelectedScenarioId] = useState(demoArtifact?.scenarios[0]?.scenarioId || '');
  const selectedScenario = demoArtifact?.scenarios.find((scenario) => scenario.scenarioId === selectedScenarioId)
    || demoArtifact?.scenarios[0];
  const pipelineMetrics = [
    ['Records adjusted', value(summary.alertsAdjusted)],
    ['Direct feedback count', value(summary.directFeedbackAppliedCount)],
    ['Exception memory applied', value(summary.exceptionMemoryAppliedCount)],
    ['Score adjustment guardrails', value(summary.scoreAdjustmentGuardrailCount)],
    ['Exception trust-gate rejections', value(summary.exceptionRejectedByTrustGateCount)],
    ['Review queue before', value(summary.reviewQueueBefore)],
    ['Review queue after', value(summary.reviewQueueAfter)],
    ['Average Detection Score', formatScore(summary.averageRiskBeforeFeedback)],
    ['Average Operational Priority', formatScore(summary.averageRiskAfterFeedback)],
  ];
  const sessionMetrics = [
    ['Session actions applied', value(sessionKpis.localFeedbackApplied)],
    ['Confirmed threats', value(sessionKpis.confirmedThreats)],
    ['False positives marked', value(sessionKpis.falsePositivesMarked)],
    ['Expected activity marked', value(sessionKpis.expectedActivityMarked)],
    ['Needs investigation', value(sessionKpis.needsInvestigation)],
    ['Escalated alerts', value(sessionKpis.escalatedAlerts)],
    ['Average priority change', formatScore(sessionKpis.averageRiskChange)],
    ['Guardrails triggered', value(sessionKpis.guardrailsTriggered)],
  ];

  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div>
          <h2>Feedback Model</h2>
          <p>Frozen calibration feedback and held-out priority evaluation</p>
        </div>
        <span className="impact-pill">No live write-back</span>
      </div>
      <div className="explain-panel">
        <h3>Three Separate Feedback Contexts</h3>
        <p>
          Formal held-out evaluation, controlled demonstrations, and temporary browser-session previews are reported separately.
          Their alerts and metrics are never combined.
        </p>
      </div>
      <div className="kpi-title feedback-panel-title">
        <strong>Formal Held-out Evaluation</strong>
        <span>{value(summary.heldOutAlertCount)} held-out records; frozen calibration feedback; manual exception memory disabled</span>
      </div>
      <div className="feedback-context-banner formal">Formal evaluation results</div>
      <div className="metric-grid">
        {pipelineMetrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>

      <section className="feedback-demo-section" aria-labelledby="hitl-demo-title">
        <div className="kpi-title feedback-panel-title">
          <strong id="hitl-demo-title">HITL Adaptation Demonstrations</strong>
          <span>{demoArtifact ? demoArtifact.summary.scenarioCount : 'N/A'} controlled scenarios processed by the real fusion and adaptation engines</span>
        </div>
        <div className="feedback-context-banner demonstration">
          <strong>Demonstration scenarios — not formal evaluation results.</strong>
          <span>Synthetic detector inputs — no actual XGBoost inference.</span>
          <span>Real Stage 4 fusion and Stage 5 adaptation logic are used.</span>
        </div>
        {!demoArtifact ? (
          <div className="artifact-error" role="alert">
            <strong>Demonstration data unavailable</strong>
            <ul>{demoErrors.map((error) => <li key={error}>{error}</li>)}</ul>
          </div>
        ) : (
          <>
            <div className="scenario-selector" role="group" aria-label="HITL adaptation demonstration scenario">
              {demoArtifact.scenarios.map((scenario) => (
                <button
                  className={scenario.scenarioId === selectedScenario?.scenarioId ? 'active' : ''}
                  key={scenario.scenarioId}
                  onClick={() => setSelectedScenarioId(scenario.scenarioId)}
                  type="button"
                >
                  {scenario.title}
                </button>
              ))}
            </div>
            {selectedScenario && (
              <div className="demo-scenario-detail">
                <div className="panel-header">
                  <div><h3>{selectedScenario.title}</h3><p>{selectedScenario.purpose}</p></div>
                  <span className="impact-pill">Controlled demo</span>
                </div>
                <AutomatedDetectionEvidence alert={selectedScenario.alert} density="compact" />
                <HitlAdaptationEvidence alert={selectedScenario.alert} density="expanded" />
              </div>
            )}
          </>
        )}
      </section>

      <div className="kpi-title feedback-panel-title">
        <strong>Browser Session Preview</strong>
        <span>Temporary local interaction; not persisted historical learning</span>
      </div>
      <div className="feedback-context-banner session">Session preview — not written back to historical feedback.</div>
      <div className="metric-grid">
        {sessionMetrics.map(([label, metric]) => (
          <article className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{metric}</strong>
          </article>
        ))}
      </div>
      <div className="explain-panel">
        <h3>Session Preview Boundary</h3>
        <p>
          This temporary browser action is not persisted and has not yet become historical feedback for future alerts.
          No JSON files are modified, and no model retraining is performed.
        </p>
      </div>
    </section>
  );
}
