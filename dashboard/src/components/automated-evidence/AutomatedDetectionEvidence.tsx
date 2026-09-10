import type { AnalystAlertV1 } from '../../types/dashboardData';
import { AdvancedModelEvidence } from './AdvancedModelEvidence';
import { DetectorStateSummary } from './DetectorStateSummary';
import { MlEvidenceSection } from './MlEvidenceSection';
import { SignatureEvidenceSection } from './SignatureEvidenceSection';
import { TreeShapExplanation } from './TreeShapExplanation';

interface AutomatedDetectionEvidenceProps {
  alert: AnalystAlertV1;
  density?: 'compact' | 'expanded';
}

export function AutomatedDetectionEvidence({ alert, density = 'compact' }: AutomatedDetectionEvidenceProps) {
  const automated = alert.automatedDetection;

  return (
    <section className={`automated-evidence automated-evidence-${density}`} aria-labelledby={`automated-evidence-${alert.identity.id}`}>
      <div className="automated-evidence-title">
        <div>
          <span>Automated evidence</span>
          <h3 id={`automated-evidence-${alert.identity.id}`}>Why this detection was produced</h3>
        </div>
        <span className={`review-state ${automated.requiresAnalystReview ? 'review-required' : 'review-not-required'}`}>
          {automated.requiresAnalystReview ? 'Analyst review required' : 'No automated review flag'}
        </span>
      </div>

      <div className="automated-summary-grid">
        <div><span>Detection Score</span><strong>{Math.round(automated.detectionScore)}</strong></div>
        <div><span>Automated attack type</span><strong>{automated.attackType}</strong></div>
        <div><span>Confidence level</span><strong>{automated.confidenceLevel || 'N/A'}</strong></div>
      </div>
      <p className="helper-text">Detection Score is the automated Signature + ML result before human-feedback adaptation.</p>

      <DetectorStateSummary alert={alert} />

      <div className="automated-evidence-grid">
        <SignatureEvidenceSection evidence={alert.signatureEvidence} />
        <MlEvidenceSection evidence={alert.mlEvidence} />
      </div>

      <TreeShapExplanation mlEvidence={alert.mlEvidence} />
      <AdvancedModelEvidence alert={alert} />
    </section>
  );
}
