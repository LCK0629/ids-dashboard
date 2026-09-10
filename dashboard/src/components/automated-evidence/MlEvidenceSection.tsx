import type { AnalystAlertV1 } from '../../types/dashboardData';
import {
  ML_CONFIDENCE_HELPER_TEXT,
  PREDICTION_MARGIN_HELPER_TEXT,
  formatEvidenceReason,
  formatModelConfidence,
  formatPredictionMargin,
  getMlAvailabilityPresentation,
} from '../../utils/automatedEvidence.js';

interface MlEvidenceSectionProps {
  evidence: AnalystAlertV1['mlEvidence'];
}

function value(input: string | number | null): string {
  return input === null || input === '' ? 'N/A' : String(input);
}

export function MlEvidenceSection({ evidence }: MlEvidenceSectionProps) {
  const availability = getMlAvailabilityPresentation(evidence);

  return (
    <section className="automated-evidence-section ml-evidence" aria-labelledby="ml-evidence-title">
      <div className="evidence-section-heading">
        <div>
          <span>XGBoost detector</span>
          <h4 id="ml-evidence-title">{availability.label}</h4>
        </div>
        <span className={`evidence-state-pill ${availability.key === 'available' ? 'matched' : 'warning'}`}>
          {availability.key}
        </span>
      </div>

      {availability.key === 'available' ? (
        <>
          <dl className="evidence-facts">
            <div><dt>Predicted class</dt><dd>{value(evidence.predictedAttackType)}</dd></div>
            <div><dt>Model confidence</dt><dd>{formatModelConfidence(evidence.modelConfidence)}</dd></div>
            <div><dt>Second-best class</dt><dd>{value(evidence.secondBestClass)}</dd></div>
            <div><dt>Prediction margin</dt><dd>{formatPredictionMargin(evidence.predictionMargin)}</dd></div>
            <div><dt>ML threat evidence score</dt><dd>{value(evidence.threatEvidenceScore)}</dd></div>
          </dl>
          <p className="helper-text">{ML_CONFIDENCE_HELPER_TEXT}</p>
          <p className="helper-text">{PREDICTION_MARGIN_HELPER_TEXT}</p>
        </>
      ) : (
        <div className="evidence-unavailable-message" role="status">
          <p>{availability.explanation}</p>
          {availability.key === 'unavailable' && (
            <p><strong>Recorded reason:</strong> {formatEvidenceReason(evidence.failureReason)}</p>
          )}
        </div>
      )}
    </section>
  );
}
