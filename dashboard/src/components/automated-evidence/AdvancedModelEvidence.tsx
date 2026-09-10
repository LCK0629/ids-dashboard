import type { AnalystAlertV1 } from '../../types/dashboardData';
import {
  formatFeatureValue,
  formatModelConfidence,
  shortenHash,
} from '../../utils/automatedEvidence.js';

interface AdvancedModelEvidenceProps {
  alert: AnalystAlertV1;
}

function AuditValue({ label, value, fullValue }: { label: string; value: string; fullValue?: string | null }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        {fullValue ? (
          <code className="hash-value" tabIndex={0} title={fullValue} aria-label={`${label}: ${fullValue}`}>{value}</code>
        ) : value}
      </dd>
    </div>
  );
}

export function AdvancedModelEvidence({ alert }: AdvancedModelEvidenceProps) {
  const ml = alert.mlEvidence;
  const explanation = ml.explanation;
  const provenance = ml.modelProvenance;
  const probabilities = Object.entries(ml.classProbabilities || {}).sort((left, right) => right[1] - left[1]);

  return (
    <details className="evidence-disclosure advanced-model-evidence">
      <summary>Advanced model and detector evidence</summary>
      <div className="advanced-evidence-content">
        <dl className="advanced-evidence-grid">
          <AuditValue label="Raw fusion decision" value={alert.automatedDetection.fusionDecision} />
          <AuditValue label="Predicted class index" value={ml.predictedClassIndex === null ? 'N/A' : String(ml.predictedClassIndex)} />
          <AuditValue label="ML threat evidence score" value={ml.threatEvidenceScore === null ? 'N/A' : String(ml.threatEvidenceScore)} />
          <AuditValue label="Schema mode" value={ml.schemaMode} />
          <AuditValue label="TreeSHAP method" value={explanation.method || 'N/A'} />
          <AuditValue label="SHAP output space" value={explanation.outputSpace || 'N/A'} />
          <AuditValue label="Base value" value={formatFeatureValue(explanation.baseValue)} />
          <AuditValue label="Raw model margin" value={formatFeatureValue(explanation.rawModelMargin)} />
          <AuditValue label="Additivity passed" value={explanation.additivityCheck ? (explanation.additivityCheck.passed ? 'Yes' : 'No') : 'N/A'} />
          <AuditValue label="Additivity difference" value={formatFeatureValue(explanation.additivityCheck?.difference)} />
          <AuditValue label="Additivity tolerance" value={formatFeatureValue(explanation.additivityCheck?.tolerance)} />
          <AuditValue label="XGBoost version" value={provenance?.xgboostVersion || 'N/A'} />
          <AuditValue label="Model SHA-256" value={shortenHash(provenance?.modelSha256)} fullValue={provenance?.modelSha256} />
          <AuditValue label="Feature schema SHA-256" value={shortenHash(provenance?.featureSchemaSha256)} fullValue={provenance?.featureSchemaSha256} />
          <AuditValue label="Preprocessing config SHA-256" value={shortenHash(provenance?.preprocessingConfigSha256)} fullValue={provenance?.preprocessingConfigSha256} />
          <AuditValue label="Label mapping SHA-256" value={shortenHash(provenance?.labelMappingSha256)} fullValue={provenance?.labelMappingSha256} />
        </dl>

        <section className="probability-section">
          <h5>Class probabilities</h5>
          {probabilities.length > 0 ? (
            <dl className="probability-list">
              {probabilities.map(([className, probability]) => (
                <div key={className}><dt>{className}</dt><dd>{formatModelConfidence(probability)}</dd></div>
              ))}
            </dl>
          ) : <p className="helper-text">No class probabilities are available.</p>}
          <p className="helper-text">Raw XGBoost softprob outputs; they are not calibrated certainty.</p>
        </section>
      </div>
    </details>
  );
}
