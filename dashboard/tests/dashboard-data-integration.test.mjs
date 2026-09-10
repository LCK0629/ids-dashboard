import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

import analystArtifact from '../src/data/analyst-alerts.v1.json' with { type: 'json' };
import demoArtifact from '../src/data/adaptation-demo-scenarios.v1.json' with { type: 'json' };
import evaluatorArtifact from '../src/data/evaluator-summary.v1.json' with { type: 'json' };
import {
  ANALYST_ARTIFACT_TYPE,
  ANALYST_SCHEMA_VERSION,
  DEMO_ARTIFACT_TYPE,
  findForbiddenGroundTruthPaths,
  validateEvaluatorArtifact,
  validateAnalystAlert,
  validateAnalystArtifact,
  validateStage5DashboardSourceRecord,
} from '../src/data-contract/analystDashboardContract.js';
import {
  buildAnalystAlert,
  buildAnalystArtifact,
  findPrivacyViolations,
  parseArgs as parseExporterArgs,
  sortAnalystAlerts,
} from '../scripts/export-dashboard-data.mjs';
import { buildDemoScenarioArtifact } from '../scripts/generate-adaptation-demo-scenarios.mjs';

const require = createRequire(import.meta.url);
const stage5Runner = require('../../stage-5/scripts/run-feedback-demo.js');
const stage5Core = require('../../stage-5/core/feedback-engine.js');
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const adaptationConfig = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'stage-5', 'config', 'adaptation-config.json'), 'utf8')
);

function validExplanation() {
  return {
    status: 'available',
    method: 'xgboost_native_treeshap_pred_contribs',
    outputSpace: 'raw_margin',
    explainedClass: 'DoS',
    explainedClassIndex: 4,
    baseValue: 0.25,
    rawModelMargin: 1.5,
    topSupportingFeatures: [
      { featureName: 'Flow Duration', featureValue: 100, shapContribution: 1.3, direction: 'supports_prediction' },
    ],
    topOpposingFeatures: [
      { featureName: 'ACK Flag Cnt', featureValue: 2, shapContribution: -0.05, direction: 'opposes_prediction' },
    ],
    additivityCheck: { passed: true, difference: 0, tolerance: 0.0001 },
  };
}

function validAdaptationDiagnostics() {
  return {
    evaluated: true,
    similarity: {
      averageScore: 0.9,
      averageEvidenceCoverage: 1,
      threshold: 0.7,
      minimumEvidenceCoverage: 0.6,
      matchedCount: 3,
      lowSimilarityAttemptCount: 0,
      lowEvidenceCoverageAttemptCount: 0,
    },
    historicalFeedback: {
      counts: { falsePositive: 3, confirmedThreat: 0, expectedActivity: 0 },
      dominantFeedback: 'mark_false_positive',
      agreementRatio: 1,
      conflictDetected: false,
    },
    eligibilityThresholds: {
      minimumFeedbackCount: 3,
      minimumAgreementRatio: 0.67,
      strongAgreementRatio: 0.85,
    },
    matchedExamples: [
      {
        feedbackId: 'FB-1',
        historicalAlertId: 'AL-HIST-1',
        feedbackType: 'mark_false_positive',
        similarityScore: 0.9,
        evidenceCoverage: 1,
        matchedFields: ['fusionAttackType', 'destinationPort'],
        differedFields: [],
        unavailableFields: [],
      },
    ],
  };
}

function validStage5Alert(id = 'TEST-001', overrides = {}) {
  return {
    id,
    flowFeatureSummary: { protocol: 'TCP', destinationPort: 80, flowDuration: 100 },
    signatureHit: false,
    signatureId: null,
    signatureAttackType: null,
    signatureSeverity: null,
    signaturePlainExplanation: null,
    matchedConditionsReadable: [],
    signatureTechnicalDetails: null,
    mlRecordPresent: true,
    mlPredictionStatus: 'available',
    mlEvidenceAvailable: true,
    mlFailureReason: null,
    mlSchemaMode: 'new',
    mlPredictedClassIndex: 4,
    mlPredictedAttackType: 'DoS',
    modelConfidence: 0.9,
    classProbabilities: { Benign: 0.1, DoS: 0.9 },
    secondBestClass: 'Benign',
    predictionMargin: 0.8,
    modelProvenance: {
      xgboostVersion: '3.3.0',
      modelSha256: 'model-hash',
      featureSchemaSha256: 'feature-hash',
      preprocessingConfigSha256: 'preprocessing-hash',
      labelMappingSha256: 'label-hash',
    },
    mlExplanation: validExplanation(),
    mlThreatEvidenceScore: 90,
    fusionAttackType: 'DoS',
    fusionRiskScore: 80,
    fusionDecision: 'ML_ONLY_HIGH_CONFIDENCE',
    fusionEvidence: 'ML-only evidence.',
    fusionConfidenceLevel: 'High',
    requiresAnalystReviewBeforeFeedback: true,
    requiresAnalystReview: true,
    detectionScore: 80,
    operationalPriorityScore: 65,
    feedbackApplied: true,
    feedbackRecorded: false,
    priorityAdjusted: true,
    feedbackAdjustment: -15,
    proposedFeedbackAdjustment: -25,
    cappedFeedbackAdjustment: -25,
    feedbackGuardrailsApplied: ['critical_alert_floor'],
    guardrailInterventions: [{ code: 'critical_alert_floor', configuredValue: 70, appliedValue: 70 }],
    analystFeedbackStatus: 'adjusted_by_historical_feedback',
    adaptationSource: 'historical_feedback',
    adaptationEligible: true,
    adaptationEligibilityReason: 'Similarity and agreement passed.',
    adaptationExplanation: 'Detection Score was adjusted by historical feedback.',
    similarityMatched: true,
    similarityReason: 'Matched three records.',
    matchedHistoricalFeedbackCount: 3,
    matchedHistoricalFeedbackIds: ['FB-1', 'FB-2', 'FB-3'],
    dominantHistoricalFeedback: 'mark_false_positive',
    historicalAgreementRatio: 1,
    conflictDetected: false,
    lowEvidenceCoverageCount: 0,
    lowSimilarityCount: 0,
    matchedFeedbackId: null,
    adaptationDiagnostics: validAdaptationDiagnostics(),
    ...overrides,
  };
}

function clone(value) {
  return structuredClone(value);
}

test('analyst artifact uses the supported schema version', () => {
  assert.equal(analystArtifact.schemaVersion, ANALYST_SCHEMA_VERSION);
});

test('analyst artifact type is operational data', () => {
  assert.equal(analystArtifact.artifactType, ANALYST_ARTIFACT_TYPE);
});

test('complete generated analyst artifact passes runtime validation', () => {
  assert.deepEqual(validateAnalystArtifact(analystArtifact), { valid: true, errors: [] });
});

test('generated analyst alert IDs are non-empty and unique', () => {
  const ids = analystArtifact.alerts.map((alert) => alert.identity.id);
  assert.ok(ids.every((id) => typeof id === 'string' && id.trim()));
  assert.equal(new Set(ids).size, ids.length);
});

test('Detection Score is required', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.automatedDetection.detectionScore = null;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('Operational Priority is required', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.adaptation.operationalPriorityScore = null;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('score bounds are enforced', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.adaptation.operationalPriorityScore = 101;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('complete analyst artifact contains no recursive ground-truth keys', () => {
  assert.deepEqual(findForbiddenGroundTruthPaths(analystArtifact), []);
});

test('unavailable ML state is preserved', () => {
  const alert = buildAnalystAlert(validStage5Alert('U', {
    mlRecordPresent: true,
    mlPredictionStatus: 'unavailable',
    mlEvidenceAvailable: false,
    mlFailureReason: 'invalid_numeric_feature_values',
    mlPredictedClassIndex: null,
    mlPredictedAttackType: null,
    modelConfidence: null,
    classProbabilities: null,
    secondBestClass: null,
    predictionMargin: null,
    mlThreatEvidenceScore: null,
    mlExplanation: { status: 'unavailable', reason: 'prediction_unavailable' },
  }));
  assert.equal(alert.mlEvidence.recordPresent, true);
  assert.equal(alert.mlEvidence.predictionStatus, 'unavailable');
  assert.equal(alert.mlEvidence.failureReason, 'invalid_numeric_feature_values');
});

test('missing ML record is distinct from unavailable ML', () => {
  const missing = buildAnalystAlert(validStage5Alert('M', {
    mlRecordPresent: false,
    mlPredictionStatus: 'missing_record',
    mlEvidenceAvailable: false,
    mlFailureReason: null,
    mlPredictedClassIndex: null,
    mlPredictedAttackType: null,
    modelConfidence: null,
    classProbabilities: null,
    secondBestClass: null,
    predictionMargin: null,
    mlThreatEvidenceScore: null,
    mlExplanation: { status: 'unavailable', reason: 'no_ml_record' },
  }));
  assert.equal(missing.mlEvidence.recordPresent, false);
  assert.equal(missing.mlEvidence.predictionStatus, 'missing_record');
});

test('model provenance is preserved', () => {
  const source = validStage5Alert();
  const exported = buildAnalystAlert(source).mlEvidence.modelProvenance;
  for (const [key, value] of Object.entries(source.modelProvenance)) {
    assert.equal(exported[key], value);
  }
});

test('available TreeSHAP explanation is preserved', () => {
  const source = validStage5Alert();
  const exported = buildAnalystAlert(source).mlEvidence.explanation;
  assert.equal(exported.status, source.mlExplanation.status);
  assert.equal(exported.method, source.mlExplanation.method);
  assert.equal(exported.outputSpace, source.mlExplanation.outputSpace);
  assert.equal(exported.explainedClass, source.mlExplanation.explainedClass);
  assert.equal(exported.explainedClassIndex, source.mlExplanation.explainedClassIndex);
  assert.equal(exported.baseValue, source.mlExplanation.baseValue);
  assert.equal(exported.rawModelMargin, source.mlExplanation.rawModelMargin);
  assert.deepEqual(exported.topSupportingFeatures, source.mlExplanation.topSupportingFeatures);
  assert.deepEqual(exported.topOpposingFeatures, source.mlExplanation.topOpposingFeatures);
  assert.deepEqual(exported.additivityCheck, source.mlExplanation.additivityCheck);
});

test('unavailable TreeSHAP explanation is preserved', () => {
  const source = validStage5Alert('E', {
    mlExplanation: { status: 'unavailable', reason: 'additivity_check_failed', method: 'native' },
  });
  const explanation = buildAnalystAlert(source).mlEvidence.explanation;
  assert.equal(explanation.status, 'unavailable');
  assert.equal(explanation.reason, 'additivity_check_failed');
});

test('exporter does not recalculate SHAP contributions', () => {
  const source = validStage5Alert();
  assert.equal(
    buildAnalystAlert(source).mlEvidence.explanation.topSupportingFeatures[0].shapContribution,
    source.mlExplanation.topSupportingFeatures[0].shapContribution
  );
});

test('exporter does not modify Detection Score', () => {
  assert.equal(buildAnalystAlert(validStage5Alert()).automatedDetection.detectionScore, 80);
});

test('exporter does not modify Operational Priority', () => {
  assert.equal(buildAnalystAlert(validStage5Alert()).adaptation.operationalPriorityScore, 65);
});

test('artifact ordering is deterministic by priority, review, and ID', () => {
  const alerts = [
    buildAnalystAlert(validStage5Alert('B', { operationalPriorityScore: 40 })),
    buildAnalystAlert(validStage5Alert('A', { operationalPriorityScore: 80 })),
  ];
  assert.deepEqual(sortAnalystAlerts(alerts).map((alert) => alert.identity.id), ['A', 'B']);
});

test('artifact generation is deterministic', () => {
  const source = [validStage5Alert()];
  assert.equal(JSON.stringify(buildAnalystArtifact(source)), JSON.stringify(buildAnalystArtifact(source)));
});

test('duplicate alert IDs are rejected', () => {
  assert.throws(() => buildAnalystArtifact([validStage5Alert('D'), validStage5Alert('D')]));
});

test('malformed analyst schema is rejected', () => {
  assert.equal(validateAnalystArtifact({ schemaVersion: ANALYST_SCHEMA_VERSION }).valid, false);
});

test('unsupported schema version is rejected', () => {
  const artifact = clone(analystArtifact);
  artifact.schemaVersion = 'ids-dashboard-analyst-v2';
  assert.equal(validateAnalystArtifact(artifact).valid, false);
});

test('modern Stage 5 dashboard source record passes source validation', () => {
  assert.deepEqual(validateStage5DashboardSourceRecord(validStage5Alert()), { valid: true, errors: [] });
});

test('old committed Stage 5 sample is rejected as incompatible source', () => {
  const staleSource = JSON.parse(
    fs.readFileSync(path.join(repoRoot, 'stage-5', 'outputs', 'feedback-adjusted-alerts.sample.json'), 'utf8')
  );
  assert.throws(
    () => buildAnalystArtifact(staleSource),
    /Incompatible Stage 5 dashboard source/
  );
});

test('dashboard exporter requires explicit full-schema source paths', () => {
  assert.throws(
    () => parseExporterArgs([]),
    /Explicit --analyst-input, --feedback-summary, and --fusion-summary paths are required/
  );
});

test('ground-truth key naming variants are rejected recursively', () => {
  const variants = [
    'groundTruth', 'ground_truth', 'ground-truth',
    'trueAttackType', 'true_attack_type', 'true-attack-type',
    'rawLabel', 'raw_label', 'actualLabel', 'actual_label',
    'isMaliciousGroundTruth', 'is_malicious_ground_truth',
  ];
  variants.forEach((key) => {
    const artifact = clone(analystArtifact);
    artifact.alerts[0].mlEvidence.debug = { nested: { [key]: 'forbidden' } };
    assert.equal(validateAnalystArtifact(artifact).valid, false, `${key} should be rejected`);
  });
});

test('no-record ML state cannot carry prediction evidence or usable SHAP', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  Object.assign(alert.mlEvidence, {
    recordPresent: false,
    evidenceAvailable: false,
    predictionStatus: 'missing_record',
  });
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('unavailable ML state cannot carry prediction evidence', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  Object.assign(alert.mlEvidence, {
    evidenceAvailable: false,
    predictionStatus: 'unavailable',
    failureReason: 'invalid_numeric_feature_values',
    explanation: { status: 'unavailable', reason: 'prediction_unavailable' },
  });
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('available ML evidence requires available prediction status', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.mlEvidence.predictionStatus = 'unavailable';
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('available prediction may retain an unavailable TreeSHAP explanation', () => {
  const alert = buildAnalystAlert(validStage5Alert('SHAP-U', {
    mlExplanation: { status: 'unavailable', reason: 'additivity_check_failed', method: 'native' },
  }));
  assert.equal(validateAnalystAlert(alert).valid, true);
});

test('available SHAP class mismatch is rejected', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.mlEvidence.explanation.explainedClass = 'DDoS';
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('available SHAP class index mismatch is rejected', () => {
  const alert = buildAnalystAlert(validStage5Alert());
  alert.mlEvidence.explanation.explainedClassIndex = 3;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('analyst summary counts must agree with alert records', () => {
  const artifact = clone(analystArtifact);
  artifact.summary.mlPredictionAvailableCount -= 1;
  assert.equal(validateAnalystArtifact(artifact).valid, false);
});

test('current evaluator envelope passes runtime validation', () => {
  assert.deepEqual(validateEvaluatorArtifact(evaluatorArtifact), { valid: true, errors: [] });
});

test('wrong evaluator schema version is rejected', () => {
  const artifact = clone(evaluatorArtifact);
  artifact.schemaVersion = 'ids-dashboard-analyst-v2';
  assert.equal(validateEvaluatorArtifact(artifact).valid, false);
});

test('wrong evaluator artifact type is rejected', () => {
  const artifact = clone(evaluatorArtifact);
  artifact.artifactType = 'analyst_operational_data';
  assert.equal(validateEvaluatorArtifact(artifact).valid, false);
});

test('missing evaluator fusion summary is rejected', () => {
  const artifact = clone(evaluatorArtifact);
  delete artifact.fusionSummary;
  assert.equal(validateEvaluatorArtifact(artifact).valid, false);
});

test('missing evaluator feedback summary is rejected', () => {
  const artifact = clone(evaluatorArtifact);
  delete artifact.feedbackSummary;
  assert.equal(validateEvaluatorArtifact(artifact).valid, false);
});

test('Stage 5 runner accepts custom fused input and output directories', (context) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ids-stage5b-'));
  context.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const outputDir = path.join(tempRoot, 'outputs');
  const evaluationDir = path.join(tempRoot, 'evaluation');
  stage5Runner.main([
    '--fused-alerts', path.join(repoRoot, 'stage-4', 'outputs', 'fusion-alerts.sample.json'),
    '--output-dir', outputDir,
    '--evaluation-dir', evaluationDir,
  ]);
  assert.ok(fs.existsSync(path.join(outputDir, 'feedback-adjusted-alerts.sample.json')));
  assert.ok(fs.existsSync(path.join(evaluationDir, 'feedback-evaluation-summary.json')));
});

test('Stage 5 core preserves Detection Score semantics', () => {
  const guarded = stage5Core.applyGuardrails({ fusionRiskScore: 80 }, -10, adaptationConfig.guardrails);
  assert.equal(guarded.detectionScore, 80);
  assert.equal(guarded.operationalPriorityScore, 70);
});

test('cold-start scenario applies no adaptation', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'cold_start');
  assert.equal(scenario.alert.adaptation.operationalPriorityScore, scenario.alert.automatedDetection.detectionScore);
  assert.equal(scenario.alert.adaptation.eligible, false);
});

test('repeated false-positive scenario adapts downward', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'repeated_false_positive');
  assert.equal(scenario.alert.adaptation.eligible, true);
  assert.ok(scenario.alert.adaptation.appliedAdjustment < 0);
});

test('confirmed-threat scenario adapts upward', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'confirmed_threat');
  assert.equal(scenario.alert.adaptation.eligible, true);
  assert.ok(scenario.alert.adaptation.appliedAdjustment > 0);
});

test('conflicting history produces no adaptation', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'conflicting_history');
  assert.equal(scenario.alert.adaptation.conflictDetected, true);
  assert.equal(scenario.alert.adaptation.appliedAdjustment, 0);
});

test('guardrail scenario preserves configured floor', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'guardrail_protection');
  assert.ok(scenario.alert.adaptation.guardrailInterventions.length > 0);
  assert.equal(scenario.alert.adaptation.operationalPriorityScore, adaptationConfig.guardrails.criticalFloor);
});

test('ML-unavailable scenario does not become a Benign prediction', () => {
  const scenario = demoArtifact.scenarios.find((item) => item.scenarioId === 'ml_unavailable');
  assert.equal(scenario.alert.mlEvidence.evidenceAvailable, false);
  assert.equal(scenario.alert.mlEvidence.predictedAttackType, null);
  assert.notEqual(scenario.alert.automatedDetection.attackType, 'Benign');
});

test('demonstration scenarios are explicitly non-evaluation artifacts', () => {
  assert.equal(demoArtifact.artifactType, DEMO_ARTIFACT_TYPE);
  assert.equal(demoArtifact.generationMetadata.formalEvaluationResult, false);
});

test('analyst artifact privacy scan contains no local paths or credentials', () => {
  assert.deepEqual(findPrivacyViolations(analystArtifact), []);
});

test('generated scenario artifact is deterministic', () => {
  assert.equal(
    JSON.stringify(buildDemoScenarioArtifact(adaptationConfig)),
    JSON.stringify(buildDemoScenarioArtifact(adaptationConfig))
  );
});

test('forbidden evaluator fields are rejected even when deeply nested', () => {
  const artifact = clone(analystArtifact);
  artifact.alerts[0].mlEvidence.debug = { rawLabel: 'Benign' };
  assert.equal(validateAnalystArtifact(artifact).valid, false);
});
