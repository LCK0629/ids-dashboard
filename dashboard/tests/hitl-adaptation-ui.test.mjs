import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

import analystArtifact from '../src/data/analyst-alerts.v1.json' with { type: 'json' };
import demoArtifact from '../src/data/adaptation-demo-scenarios.v1.json' with { type: 'json' };
import evaluatorArtifact from '../src/data/evaluator-summary.v1.json' with { type: 'json' };
import {
  findForbiddenGroundTruthPaths,
  validateDemoArtifact,
} from '../src/data-contract/analystDashboardContract.js';
import { sortAnalystAlerts } from '../scripts/export-dashboard-data.mjs';
import { buildDemoScenarioArtifact } from '../scripts/generate-adaptation-demo-scenarios.mjs';

const require = createRequire(import.meta.url);
const { fuseAlert } = require('../../stage-4/core/fusion-engine.js');
const { buildAdaptationDiagnostics } = require('../../stage-5/core/feedback-engine.js');
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const adaptationConfig = JSON.parse(fs.readFileSync(path.join(repoRoot, 'stage-5/config/adaptation-config.json'), 'utf8'));
const generatorSource = fs.readFileSync(path.join(repoRoot, 'dashboard/scripts/generate-adaptation-demo-scenarios.mjs'), 'utf8');
const hitlSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/hitl-adaptation/HitlAdaptationEvidence.tsx'), 'utf8');
const feedbackPanelSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/FeedbackSummaryPanel.tsx'), 'utf8');
const appSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/App.tsx'), 'utf8');

function scenario(id) {
  const found = demoArtifact.scenarios.find((item) => item.scenarioId === id);
  assert.ok(found, `Missing demonstration scenario: ${id}`);
  return found.alert;
}

function syntheticFusionInput() {
  return fuseAlert(
    {
      id: 'CHECK-COLD', protocol: 'TCP', destinationPort: 443, flowDuration: 1200,
      totalFwdPackets: 24, totalBwdPackets: 8, flowPacketsPerSecond: 26.7,
      flowBytesPerSecond: 4800, packetLengthMean: 180, synFlagCount: 2,
      ackFlagCount: 8, signatureHit: false, signatureId: null,
      signatureAttackType: null, signatureSeverity: null,
      matchedConditionsReadable: [], signatureTechnicalDetails: null,
    },
    {
      id: 'CHECK-COLD', predictionStatus: 'available', predictedClassIndex: 4,
      predictedAttackType: 'DoS', modelConfidence: 0.82,
      classProbabilities: { Benign: 0.18, DoS: 0.82 }, secondBestClass: 'Benign',
      predictionMargin: 0.64, modelProvenance: null,
      mlExplanation: { status: 'unavailable', reason: 'demonstration_scenario_no_model_run', method: null },
    }
  );
}

function fixtureAggregation() {
  return {
    averageSimilarity: 0.86,
    averageEvidenceCoverage: 0.9,
    matchedFeedbackCount: 3,
    lowSimilarityCount: 2,
    lowEvidenceCoverageCount: 1,
    falsePositiveCount: 3,
    confirmedThreatCount: 0,
    expectedActivityCount: 0,
    dominantFeedback: 'mark_false_positive',
    agreementRatio: 1,
    conflictDetected: false,
    matchedFeedback: [{
      feedbackId: 'FB-HIST-1', alertId: 'AL-HIST-1', feedbackType: 'mark_false_positive',
      similarityScore: 0.86, evidenceCoverage: 0.9,
      matchedFields: ['fusionAttackType', 'protocol'],
      differedFields: ['fusionDecision'], unavailableFields: ['signatureId'],
    }],
  };
}

// Demo pipeline: synthetic detector inputs must pass through real Stage 4 and Stage 5 code.
test('1 demo current alert Detection Score is produced by real Stage 4 fuseAlert', () => {
  const fused = syntheticFusionInput();
  assert.equal(scenario('cold_start').automatedDetection.detectionScore, fused.fusionRiskScore);
  assert.match(generatorSource, /const \{ fuseAlert \} = require\('\.\.\/\.\.\/stage-4\/core\/fusion-engine\.js'\)/);
  assert.match(generatorSource, /return fuseAlert\(/);
  assert.match(generatorSource, /adjustAlertsWithFeedback\(/);
});

test('2 demo generator does not manually author final fusionRiskScore', () => {
  assert.doesNotMatch(generatorSource, /fusionRiskScore\s*:/);
});

test('3 demo generator does not manually author final fusionDecision', () => {
  assert.doesNotMatch(generatorSource, /fusionDecision\s*:/);
});

test('4 demo generator does not manually author final fusionConfidenceLevel', () => {
  assert.doesNotMatch(generatorSource, /fusionConfidenceLevel\s*:/);
});

test('5 repeated false-positive scenario adapts downward', () => {
  const alert = scenario('repeated_false_positive');
  assert.equal(alert.adaptation.eligible, true);
  assert.ok(alert.adaptation.appliedAdjustment < 0);
  assert.ok(alert.adaptation.operationalPriorityScore < alert.automatedDetection.detectionScore);
});

test('6 confirmed-threat scenario adapts upward', () => {
  const alert = scenario('confirmed_threat');
  assert.equal(alert.adaptation.eligible, true);
  assert.ok(alert.adaptation.appliedAdjustment > 0);
  assert.ok(alert.adaptation.operationalPriorityScore > alert.automatedDetection.detectionScore);
});

test('7 conflicting history applies zero adjustment', () => {
  const alert = scenario('conflicting_history');
  assert.equal(alert.adaptation.conflictDetected, true);
  assert.equal(alert.adaptation.appliedAdjustment, 0);
});

test('8 cold start keeps Operational Priority equal to Detection Score', () => {
  const alert = scenario('cold_start');
  assert.equal(alert.adaptation.operationalPriorityScore, alert.automatedDetection.detectionScore);
  assert.equal(alert.adaptation.appliedAdjustment, 0);
});

test('9 guardrail scenario invokes a real configured guardrail', () => {
  const alert = scenario('guardrail_protection');
  assert.equal(alert.adaptation.guardrailsApplied.includes('critical_alert_floor'), true);
  assert.equal(alert.adaptation.operationalPriorityScore, adaptationConfig.guardrails.criticalFloor);
  assert.notEqual(alert.adaptation.proposedAdjustment, alert.adaptation.appliedAdjustment);
});

test('10 ML-unavailable scenario preserves Stage 4 unavailable handling', () => {
  const alert = scenario('ml_unavailable');
  assert.equal(alert.mlEvidence.predictionStatus, 'unavailable');
  assert.equal(alert.mlEvidence.predictedAttackType, null);
  assert.equal(alert.automatedDetection.detectorState, 'signature_only');
  assert.equal(alert.signatureEvidence.hit, true);
});

test('11 demo metadata identifies real Stage 4 and Stage 5 authorities', () => {
  assert.equal(demoArtifact.generationMetadata.automatedDetectionAuthority, 'stage-4/core/fusion-engine.js');
  assert.equal(demoArtifact.generationMetadata.adaptationAuthority, 'stage-5/core/feedback-engine.js');
  assert.equal(demoArtifact.generationMetadata.generationMode, 'deterministic_stage4_stage5_demonstration');
});

test('12 demo is explicitly non-evaluation data and passes runtime validation', () => {
  assert.equal(demoArtifact.generationMetadata.formalEvaluationResult, false);
  assert.equal(demoArtifact.generationMetadata.actualXgboostInference, false);
  assert.deepEqual(validateDemoArtifact(demoArtifact), { valid: true, errors: [] });
  assert.equal(JSON.stringify(buildDemoScenarioArtifact(adaptationConfig)), JSON.stringify(demoArtifact));
});

// Explanation propagation: use the Stage 5 snapshot builder as the authority.
test('13 average similarity is preserved from Stage 5 aggregation', () => {
  assert.equal(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).similarity.averageScore, 0.86);
});

test('14 similarity threshold is preserved from configuration, not recomputed', () => {
  assert.equal(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).similarity.threshold, adaptationConfig.similarity.threshold);
});

test('15 evidence coverage is preserved where available', () => {
  assert.equal(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).similarity.averageEvidenceCoverage, 0.9);
});

test('16 matched fields are preserved', () => {
  assert.deepEqual(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).matchedExamples[0].matchedFields, ['fusionAttackType', 'protocol']);
});

test('17 differed fields are preserved', () => {
  assert.deepEqual(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).matchedExamples[0].differedFields, ['fusionDecision']);
});

test('18 unavailable fields are preserved', () => {
  assert.deepEqual(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).matchedExamples[0].unavailableFields, ['signatureId']);
});

test('19 feedback-type counts are preserved', () => {
  assert.deepEqual(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).historicalFeedback.counts, {
    falsePositive: 3, confirmedThreat: 0, expectedActivity: 0,
  });
});

test('20 agreement ratio is preserved', () => {
  assert.equal(buildAdaptationDiagnostics(fixtureAggregation(), adaptationConfig).historicalFeedback.agreementRatio, 1);
});

test('21 conflict state is preserved', () => {
  const aggregation = { ...fixtureAggregation(), conflictDetected: true, dominantFeedback: null };
  const diagnostics = buildAdaptationDiagnostics(aggregation, adaptationConfig);
  assert.equal(diagnostics.historicalFeedback.conflictDetected, true);
  assert.equal(diagnostics.historicalFeedback.dominantFeedback, null);
});

test('22 explanation diagnostics do not alter Detection Score', () => {
  const alert = scenario('repeated_false_positive');
  assert.equal(alert.automatedDetection.detectionScore, 80);
  assert.equal(alert.adaptation.diagnostics.similarity.averageScore, 1);
});

test('23 explanation diagnostics do not alter Operational Priority', () => {
  const alert = scenario('repeated_false_positive');
  assert.equal(alert.adaptation.operationalPriorityScore, 55);
});

test('24 explanation diagnostics do not change formal queue ordering', () => {
  const before = analystArtifact.alerts.map((alert) => alert.identity.id);
  const cloned = structuredClone(analystArtifact.alerts);
  cloned.forEach((alert) => { alert.adaptation.diagnostics.evaluated = !alert.adaptation.diagnostics.evaluated; });
  assert.deepEqual(sortAnalystAlerts(cloned).map((alert) => alert.identity.id), before);
});

test('25 Stage 5 formal evaluation counts remain unchanged', () => {
  assert.deepEqual({
    records: analystArtifact.summary.recordCount,
    matches: analystArtifact.summary.similarityMatchCount,
    eligible: analystArtifact.summary.adaptationEligibleCount,
    adapted: analystArtifact.summary.actualAdaptationCount,
  }, { records: 995, matches: 204, eligible: 0, adapted: 0 });
});

// UI semantics and separation boundaries.
test('26 Detection Score is labelled immutable and automated', () => {
  assert.match(hitlSource, /title="Detection Score" status="IMMUTABLE"/);
  assert.match(hitlSource, /Immutable automated Signature \+ ML result before historical feedback/);
  assert.match(hitlSource, /alert\.automatedDetection\.detectionScore/);
});

test('27 similarity is labelled applicability rather than threat probability', () => {
  assert.match(hitlSource, /Similarity \/ Applicability/);
  assert.match(hitlSource, /not the probability of an attack/);
  assert.doesNotMatch(hitlSource, /threat probability/i);
});

test('28 historical agreement is explicitly not ground truth', () => {
  assert.match(hitlSource, /Agreement indicates consistency in past analyst outcomes, not truth/);
  assert.match(hitlSource, /Historical analyst feedback is operational evidence, not ground truth/);
});

test('29 eligibility state is visible', () => {
  assert.match(hitlSource, /title="Eligibility"/);
  assert.match(hitlSource, /'ELIGIBLE' : 'NOT ELIGIBLE'/);
});

test('30 proposed, capped, and applied adjustments remain distinct', () => {
  assert.match(hitlSource, /<dt>Proposed<\/dt>/);
  assert.match(hitlSource, /<dt>Capped<\/dt>/);
  assert.match(hitlSource, /<dt>Applied<\/dt>/);
});

test('31 guardrail intervention is visible with configured and applied values', () => {
  assert.match(hitlSource, /title="Guardrail"/);
  assert.match(hitlSource, /configuredValue/);
  assert.match(hitlSource, /appliedValue/);
});

test('32 cold-start no-adaptation reason is visible in canonical data', () => {
  assert.match(scenario('cold_start').adaptation.eligibilityReason, /Cold start/i);
  assert.equal(scenario('cold_start').adaptation.priorityAdjusted, false);
});

test('33 insufficient-feedback explanation remains representable', () => {
  const formalAlert = analystArtifact.alerts.find((alert) => alert.adaptation.similarityMatched && !alert.adaptation.eligible);
  assert.ok(formalAlert);
  assert.match(formalAlert.adaptation.eligibilityReason, /Required 3, found/i);
});

test('34 conflict state and reason are visible', () => {
  const alert = scenario('conflicting_history');
  assert.equal(alert.adaptation.diagnostics.historicalFeedback.conflictDetected, true);
  assert.match(alert.adaptation.eligibilityReason, /conflict/i);
});

test('35 successful downward adaptation is visible', () => {
  const alert = scenario('repeated_false_positive');
  assert.deepEqual([alert.automatedDetection.detectionScore, alert.adaptation.operationalPriorityScore], [80, 55]);
});

test('36 successful upward adaptation is visible', () => {
  const alert = scenario('confirmed_threat');
  assert.deepEqual([alert.automatedDetection.detectionScore, alert.adaptation.operationalPriorityScore], [59, 74]);
});

test('37 demo is prominently marked as non-evaluation', () => {
  assert.match(feedbackPanelSource, /Demonstration scenarios . not formal evaluation results\./);
});

test('38 demo alerts are not included in the formal queue', () => {
  const formalIds = new Set(analystArtifact.alerts.map((alert) => alert.identity.id));
  assert.equal(demoArtifact.scenarios.some((item) => formalIds.has(item.alert.identity.id)), false);
});

test('39 demo metrics are not included in formal evaluator metrics', () => {
  assert.equal(evaluatorArtifact.feedbackSummary.heldOutAlertCount, 995);
  assert.equal(demoArtifact.summary.scenarioCount, 6);
  assert.match(feedbackPanelSource, /Their alerts and metrics are never combined/);
});

test('40 browser session preview is visually distinct from historical adaptation', () => {
  assert.match(feedbackPanelSource, /Browser Session Preview/);
  assert.match(feedbackPanelSource, /not persisted historical learning/);
  assert.match(feedbackPanelSource, /not yet become historical feedback for future alerts/);
  assert.match(appSource, /applySessionPreviewOverrides/);
});

test('41 analyst and demonstration artifacts contain no ground-truth fields', () => {
  assert.equal(analystArtifact.summary.groundTruthFieldCount, 0);
  assert.equal(demoArtifact.summary.groundTruthFieldCount, 0);
  assert.deepEqual(findForbiddenGroundTruthPaths(analystArtifact), []);
  assert.deepEqual(findForbiddenGroundTruthPaths(demoArtifact), []);
});

test('42 malformed demo schema version is rejected', () => {
  const artifact = structuredClone(demoArtifact);
  artifact.schemaVersion = 'unsupported-demo-v2';
  assert.equal(validateDemoArtifact(artifact).valid, false);
});

test('43 duplicate demo scenario IDs are rejected', () => {
  const artifact = structuredClone(demoArtifact);
  artifact.scenarios[1].scenarioId = artifact.scenarios[0].scenarioId;
  assert.equal(validateDemoArtifact(artifact).valid, false);
});

test('44 demo ground-truth fields are rejected recursively', () => {
  const artifact = structuredClone(demoArtifact);
  artifact.scenarios[0].alert.adaptation.audit = { groundTruth: 'malicious' };
  assert.equal(validateDemoArtifact(artifact).valid, false);
});

test('45 demo authority metadata cannot be weakened', () => {
  const artifact = structuredClone(demoArtifact);
  artifact.generationMetadata.automatedDetectionAuthority = 'manual';
  assert.equal(validateDemoArtifact(artifact).valid, false);
});

test('46 matched feedback examples remain bounded in demonstration alerts', () => {
  const artifact = structuredClone(demoArtifact);
  const example = artifact.scenarios[1].alert.adaptation.diagnostics.matchedExamples[0];
  artifact.scenarios[1].alert.adaptation.diagnostics.matchedExamples = [example, example, example, example];
  assert.equal(validateDemoArtifact(artifact).valid, false);
});

test('47 demo runtime validation rejects false model-run or manual-memory provenance', () => {
  const modelClaim = structuredClone(demoArtifact);
  modelClaim.generationMetadata.actualXgboostInference = true;
  assert.equal(validateDemoArtifact(modelClaim).valid, false);

  const manualMemoryClaim = structuredClone(demoArtifact);
  manualMemoryClaim.generationMetadata.manualExceptionMemoryEnabled = true;
  assert.equal(validateDemoArtifact(manualMemoryClaim).valid, false);
});
