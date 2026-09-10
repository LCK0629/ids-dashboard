import type { ReactNode } from 'react';
import type { AnalystAlertV1 } from '../../types/dashboardData';

interface HitlAdaptationEvidenceProps {
  alert: AnalystAlertV1;
  density?: 'compact' | 'expanded';
}

const feedbackLabels: Record<string, string> = {
  mark_false_positive: 'False Positive',
  confirm_true_positive: 'Confirmed Threat',
  mark_expected_activity: 'Expected Activity',
};

const guardrailLabels: Record<string, string> = {
  critical_alert_floor: 'Critical priority floor',
  infiltration_alert_floor: 'Infiltration priority floor',
  maximum_negative_adjustment_capped: 'Maximum downward adjustment limit',
  maximum_increase_capped: 'Maximum upward adjustment limit',
  signature_ml_disagreement_review_preserved: 'Detector disagreement keeps analyst review required',
  non_finite_adjustment_rejected: 'Invalid adjustment rejected',
};

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function signed(value: number): string {
  return value > 0 ? `+${value}` : String(value);
}

function feedbackLabel(value: string | null): string {
  if (!value) return 'None';
  return feedbackLabels[value] || value.replace(/_/g, ' ');
}

function Step({ number, title, status, children }: {
  number: number;
  title: string;
  status: string;
  children: ReactNode;
}) {
  return (
    <li className="hitl-step">
      <div className="hitl-step-heading">
        <span className="hitl-step-number" aria-hidden="true">{number}</span>
        <div><h4>{title}</h4><strong>{status}</strong></div>
      </div>
      <div className="hitl-step-body">{children}</div>
    </li>
  );
}

export function HitlAdaptationEvidence({ alert, density = 'compact' }: HitlAdaptationEvidenceProps) {
  const adaptation = alert.adaptation;
  const diagnostics = adaptation.diagnostics;
  const similarity = diagnostics.similarity;
  const history = diagnostics.historicalFeedback;
  const thresholds = diagnostics.eligibilityThresholds;
  const totalHistory = history.counts.falsePositive + history.counts.confirmedThreat + history.counts.expectedActivity;
  const similarityStatus = similarity.matchedCount > 0 ? 'PASSED' : 'NO MATCH';
  const agreementStatus = history.conflictDetected
    ? 'BLOCKED'
    : totalHistory === 0
      ? 'NOT APPLICABLE'
      : history.agreementRatio >= thresholds.minimumAgreementRatio ? 'PASSED' : 'BLOCKED';
  const guardrailStatus = adaptation.guardrailInterventions.length ? 'GUARDRAIL APPLIED' : 'NOT APPLICABLE';
  const outcomeStatus = adaptation.priorityAdjusted ? 'PRIORITY ADJUSTED' : 'UNCHANGED';
  const adjustmentExplanation = adaptation.appliedAdjustment !== 0
    || (adaptation.eligible && adaptation.proposedAdjustment !== 0)
    ? adaptation.explanation
    : `No adjustment applied. ${adaptation.eligibilityReason}`;

  return (
    <section className={`hitl-adaptation ${density}`} aria-labelledby={`hitl-title-${alert.identity.id}`}>
      <div className="hitl-title-row">
        <div>
          <span className="evidence-eyebrow">HITL ADAPTATION</span>
          <h3 id={`hitl-title-${alert.identity.id}`}>Historical Feedback to Operational Priority</h3>
        </div>
        <span className="status-chip">{outcomeStatus}</span>
      </div>
      <p className="helper-text">
        Historical analyst feedback can change queue priority for similar future alerts. It does not alter automated detection or retrain XGBoost.
      </p>

      <ol className="hitl-chain">
        <Step number={1} title="Detection Score" status="IMMUTABLE">
          <strong className="hitl-score">{alert.automatedDetection.detectionScore}</strong>
          <p>Immutable automated Signature + ML result before historical feedback.</p>
        </Step>
        <Step number={2} title="Historical Feedback" status={totalHistory ? `${totalHistory} MATCHED` : 'NO HISTORY'}>
          <dl className="hitl-mini-grid">
            <div><dt>False Positive</dt><dd>{history.counts.falsePositive}</dd></div>
            <div><dt>Confirmed Threat</dt><dd>{history.counts.confirmedThreat}</dd></div>
            <div><dt>Expected Activity</dt><dd>{history.counts.expectedActivity}</dd></div>
            <div><dt>Dominant feedback</dt><dd>{feedbackLabel(history.dominantFeedback)}</dd></div>
          </dl>
          <p>Historical analyst feedback is operational evidence, not ground truth.</p>
        </Step>
        <Step number={3} title="Similarity / Applicability" status={similarityStatus}>
          <dl className="hitl-mini-grid">
            <div><dt>Average similarity</dt><dd>{similarity.matchedCount ? similarity.averageScore.toFixed(2) : 'N/A'}</dd></div>
            <div><dt>Required threshold</dt><dd>{similarity.threshold.toFixed(2)}</dd></div>
            <div><dt>Evidence coverage</dt><dd>{similarity.matchedCount ? similarity.averageEvidenceCoverage.toFixed(2) : 'N/A'}</dd></div>
            <div><dt>Minimum coverage</dt><dd>{similarity.minimumEvidenceCoverage.toFixed(2)}</dd></div>
          </dl>
          <p>Similarity measures whether previous feedback is applicable, not the probability of an attack.</p>
          {(similarity.lowSimilarityAttemptCount > 0 || similarity.lowEvidenceCoverageAttemptCount > 0) && (
            <p>
              Other comparison attempts rejected: {similarity.lowSimilarityAttemptCount} low similarity,{' '}
              {similarity.lowEvidenceCoverageAttemptCount} low evidence coverage. Valid matches above remain valid.
            </p>
          )}
        </Step>
        <Step number={4} title="Agreement / Conflict" status={agreementStatus}>
          <p>Agreement: {totalHistory ? percent(history.agreementRatio) : 'N/A'} · Required: {percent(thresholds.minimumAgreementRatio)}</p>
          <p>{history.conflictDetected ? 'Historical outcomes conflict, so no dominant disposition is trusted.' : `Dominant feedback: ${feedbackLabel(history.dominantFeedback)}.`}</p>
          <p>Agreement indicates consistency in past analyst outcomes, not truth.</p>
        </Step>
        <Step number={5} title="Eligibility" status={adaptation.eligible ? 'ELIGIBLE' : 'NOT ELIGIBLE'}>
          <p>{adaptation.eligibilityReason}</p>
          <p>Minimum similar learning feedback: {thresholds.minimumFeedbackCount}.</p>
        </Step>
        <Step number={6} title="Priority Adjustment" status={adaptation.appliedAdjustment ? 'APPLIED' : 'NO ADJUSTMENT'}>
          <dl className="hitl-mini-grid">
            <div><dt>Proposed</dt><dd>{signed(adaptation.proposedAdjustment)}</dd></div>
            <div><dt>Capped</dt><dd>{signed(adaptation.cappedAdjustment)}</dd></div>
            <div><dt>Applied</dt><dd>{signed(adaptation.appliedAdjustment)}</dd></div>
          </dl>
          <p>{adjustmentExplanation}</p>
        </Step>
        <Step number={7} title="Guardrail" status={guardrailStatus}>
          {adaptation.guardrailInterventions.length ? (
            <ul className="hitl-plain-list">
              {adaptation.guardrailInterventions.map((item, index) => (
                <li key={`${String(item.code)}-${index}`}>
                  {guardrailLabels[String(item.code)] || String(item.code)}
                  {item.configuredValue !== null && item.configuredValue !== undefined ? ` · configured ${String(item.configuredValue)}` : ''}
                  {item.originalValue !== null && item.originalValue !== undefined ? ` · attempted ${String(item.originalValue)}` : ''}
                  {item.appliedValue !== null && item.appliedValue !== undefined ? ` · applied ${String(item.appliedValue)}` : ''}
                </li>
              ))}
            </ul>
          ) : <p>No score-changing safety guardrail intervened.</p>}
        </Step>
        <Step number={8} title="Operational Priority" status={outcomeStatus}>
          <strong className="hitl-score">{adaptation.operationalPriorityScore}</strong>
          <p>Queue-ranking priority after eligible historical feedback and safety guardrails.</p>
        </Step>
      </ol>

      {density === 'expanded' && diagnostics.matchedExamples.length > 0 && (
        <details className="hitl-diagnostics">
          <summary>Matched feedback comparison details</summary>
          {diagnostics.matchedExamples.map((example) => (
            <article key={example.feedbackId}>
              <strong>{example.feedbackId} · {feedbackLabel(example.feedbackType)}</strong>
              <p>Historical alert {example.historicalAlertId} · similarity {example.similarityScore.toFixed(2)} · evidence coverage {example.evidenceCoverage.toFixed(2)}</p>
              <p>Matched: {example.matchedFields.join(', ') || 'None'}</p>
              <p>Differed: {example.differedFields.join(', ') || 'None'}</p>
              <p>Unavailable: {example.unavailableFields.join(', ') || 'None'}</p>
            </article>
          ))}
        </details>
      )}
    </section>
  );
}
