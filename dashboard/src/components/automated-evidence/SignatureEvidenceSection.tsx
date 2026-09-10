import type { AnalystAlertV1 } from '../../types/dashboardData';

interface SignatureEvidenceSectionProps {
  evidence: AnalystAlertV1['signatureEvidence'];
}

function display(value: string | null): string {
  return value || 'N/A';
}

export function SignatureEvidenceSection({ evidence }: SignatureEvidenceSectionProps) {
  return (
    <section className="automated-evidence-section signature-evidence" aria-labelledby="signature-evidence-title">
      <div className="evidence-section-heading">
        <div>
          <span>Signature detector</span>
          <h4 id="signature-evidence-title">{evidence.hit ? 'Signature matched' : 'No signature match'}</h4>
        </div>
        <span className={`evidence-state-pill ${evidence.hit ? 'matched' : 'muted'}`}>
          {evidence.hit ? 'Matched' : 'Not matched'}
        </span>
      </div>

      {evidence.hit ? (
        <>
          <dl className="evidence-facts">
            <div><dt>Rule name</dt><dd>{display(evidence.ruleName)}</dd></div>
            <div><dt>Rule ID</dt><dd>{display(evidence.ruleId)}</dd></div>
            <div><dt>Predicted attack type</dt><dd>{display(evidence.attackType)}</dd></div>
            <div><dt>Severity</dt><dd>{display(evidence.severity)}</dd></div>
          </dl>
          <p>{evidence.explanation || 'Observable flow behaviour matched a current prototype signature rule.'}</p>
          <p className="evidence-caution">A signature match is suspicious flow evidence, not proof of malicious activity.</p>
          <div className="matched-condition-group">
            <strong>Matched conditions</strong>
            {evidence.matchedConditions.length > 0 ? (
              <ul className="condition-list">
                {evidence.matchedConditions.map((condition) => <li key={condition}>{condition}</li>)}
              </ul>
            ) : <p className="helper-text">No readable conditions were supplied.</p>}
          </div>
          <details className="evidence-disclosure">
            <summary>Signature technical details</summary>
            <dl className="advanced-evidence-grid">
              <div><dt>Validation status</dt><dd>{display(evidence.technicalDetail?.validationStatus || null)}</dd></div>
              <div><dt>Rationale</dt><dd>{display(evidence.technicalDetail?.rationale || null)}</dd></div>
            </dl>
          </details>
        </>
      ) : (
        <p>No current prototype signature rule matched this flow. This does not mean the traffic is benign.</p>
      )}
    </section>
  );
}
