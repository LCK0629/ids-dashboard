import type { AnalystAlertV1 } from '../../types/dashboardData';
import { getDetectorStatePresentation } from '../../utils/automatedEvidence.js';

interface DetectorStateSummaryProps {
  alert: AnalystAlertV1;
}

export function DetectorStateSummary({ alert }: DetectorStateSummaryProps) {
  const state = getDetectorStatePresentation(alert);

  return (
    <section className={`detector-state detector-state-${state.tone || 'neutral'}`} aria-labelledby={`detector-state-${alert.identity.id}`}>
      <span>Detector state</span>
      <strong id={`detector-state-${alert.identity.id}`}>{state.label}</strong>
      <p>{state.explanation}</p>
    </section>
  );
}
