import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import analystArtifact from '../src/data/analyst-alerts.v1.json' with { type: 'json' };
import demoArtifact from '../src/data/adaptation-demo-scenarios.v1.json' with { type: 'json' };
import {
  findForbiddenGroundTruthPaths,
  validateAnalystAlert,
  validateAnalystArtifact,
} from '../src/data-contract/analystDashboardContract.js';
import {
  ML_CONFIDENCE_HELPER_TEXT,
  PREDICTION_MARGIN_HELPER_TEXT,
  SHAP_HELPER_TEXT,
  SHAP_NON_CAUSAL_TEXT,
  formatEvidenceReason,
  formatFeatureValue,
  formatModelConfidence,
  formatPredictionMargin,
  formatSignedShap,
  getDetectorStatePresentation,
  getMlAvailabilityPresentation,
  getTreeShapPresentation,
  normalizeShapGroups,
  normalizeShapWidths,
  shapDirectionLabel,
  shortenHash,
} from '../src/utils/automatedEvidence.js';

const dashboardRoot = path.resolve(import.meta.dirname, '..');

function baseAlert() {
  return {
    identity: { id: 'TEST-EVIDENCE-1' },
    flowFeatures: {},
    automatedDetection: {
      detectionScore: 82,
      attackType: 'DoS',
      requiresAnalystReview: true,
      detectorState: 'agreement',
      fusionDecision: 'SIGNATURE_ML_AGREE',
      fusionExplanation: 'Both detectors supplied evidence.',
      confidenceLevel: 'High',
    },
    signatureEvidence: {
      available: true,
      hit: true,
      ruleId: 'SIG-DOS-1',
      ruleName: 'DoS flow heuristic',
      attackType: 'DoS',
      severity: 'High',
      explanation: 'Flow characteristics match a prototype DoS heuristic.',
      matchedConditions: ['Flow packet rate exceeded the rule threshold.'],
      technicalDetail: { validationStatus: 'prototype-heuristic', rationale: 'Flow-level evidence.' },
    },
    mlEvidence: {
      recordPresent: true,
      predictionStatus: 'available',
      evidenceAvailable: true,
      failureReason: null,
      schemaMode: 'new',
      predictedClassIndex: 4,
      predictedAttackType: 'DoS',
      modelConfidence: 0.913,
      classProbabilities: { Benign: 0.04, DoS: 0.913, DDoS: 0.047 },
      secondBestClass: 'DDoS',
      predictionMargin: 0.866,
      threatEvidenceScore: 91,
      modelProvenance: {
        xgboostVersion: '3.3.0',
        modelSha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        featureSchemaSha256: 'feature-schema-hash',
        preprocessingConfigSha256: 'preprocessing-hash',
        labelMappingSha256: 'label-hash',
      },
      explanation: {
        status: 'available',
        reason: null,
        method: 'xgboost_native_treeshap_pred_contribs',
        outputSpace: 'raw_margin',
        explainedClass: 'DoS',
        explainedClassIndex: 4,
        baseValue: -0.2,
        rawModelMargin: 2.1,
        topSupportingFeatures: [
          { featureName: 'Flow Byts/s', featureValue: 1200, shapContribution: 1.25, direction: 'supports_prediction' },
          { featureName: 'SYN Flag Cnt', featureValue: 2, shapContribution: 0.25, direction: 'supports_prediction' },
        ],
        topOpposingFeatures: [
          { featureName: 'ACK Flag Cnt', featureValue: 1, shapContribution: -0.4, direction: 'opposes_prediction' },
        ],
        additivityCheck: { passed: true, difference: 0.000001, tolerance: 0.0001 },
      },
    },
    adaptation: {
      similarityMatched: false,
      similarityReason: 'No match.',
      matchedHistoricalFeedbackCount: 0,
      matchedHistoricalFeedbackIds: [],
      lowEvidenceCoverageRejectionCount: 0,
      lowSimilarityRejectionCount: 0,
      dominantHistoricalFeedback: null,
      historicalAgreementRatio: 0,
      conflictDetected: false,
      eligible: false,
      eligibilityReason: 'Cold start.',
      proposedAdjustment: 0,
      cappedAdjustment: 0,
      appliedAdjustment: 0,
      feedbackRecorded: false,
      priorityAdjusted: false,
      guardrailsApplied: [],
      guardrailInterventions: [],
      operationalPriorityScore: 82,
      source: 'none',
      explanation: 'No adaptation.',
    },
    workflow: {
      requiresAnalystReviewBeforeFeedback: true,
      requiresAnalystReview: true,
      analystFeedbackStatus: 'unchanged',
      matchedFeedbackId: null,
    },
  };
}

function clone(value) {
  return structuredClone(value);
}

function analystAlertWithAvailableExplanation() {
  const alert = analystArtifact.alerts.find((item) => item.mlEvidence.explanation.status === 'available');
  assert.ok(alert, 'Expected the analyst artifact to contain an available TreeSHAP explanation.');
  return clone(alert);
}

test('agreement has a friendly detector state', () => {
  assert.equal(getDetectorStatePresentation(baseAlert()).label, 'Signature + ML agree');
});

test('disagreement has a friendly uncertainty state', () => {
  const alert = baseAlert();
  alert.automatedDetection.detectorState = 'disagreement';
  alert.automatedDetection.fusionDecision = 'SIGNATURE_ML_DISAGREE';
  alert.mlEvidence.predictedAttackType = 'Web Attack';
  const state = getDetectorStatePresentation(alert);
  assert.equal(state.label, 'Signature / ML disagree');
  assert.match(state.explanation, /uncertainty/i);
});

test('signature matched and ML Benign is described as conflict, not correctness', () => {
  const alert = baseAlert();
  alert.automatedDetection.detectorState = 'disagreement';
  alert.automatedDetection.fusionDecision = 'SIGNATURE_ONLY_ML_BENIGN';
  alert.mlEvidence.predictedAttackType = 'Benign';
  const state = getDetectorStatePresentation(alert);
  assert.equal(state.label, 'Signature matched / ML predicts Benign');
  assert.match(state.explanation, /not a conclusion that either detector is correct/i);
});

test('ML-only state is supported', () => {
  const alert = baseAlert();
  alert.signatureEvidence.hit = false;
  alert.automatedDetection.detectorState = 'ml_only';
  assert.equal(getDetectorStatePresentation(alert).key, 'ml_only');
});

test('signature-only state is supported', () => {
  const alert = baseAlert();
  alert.automatedDetection.detectorState = 'signature_only';
  alert.mlEvidence.predictionStatus = 'unavailable';
  alert.mlEvidence.evidenceAvailable = false;
  assert.equal(getDetectorStatePresentation(alert).key, 'signature_only');
});

test('ML unavailable state is explicit', () => {
  const alert = baseAlert();
  alert.signatureEvidence.hit = false;
  alert.automatedDetection.detectorState = 'ml_unavailable';
  alert.mlEvidence.evidenceAvailable = false;
  alert.mlEvidence.predictionStatus = 'unavailable';
  assert.equal(getDetectorStatePresentation(alert).label, 'ML prediction unavailable');
});

test('ML missing state is distinct from unavailable', () => {
  const alert = baseAlert();
  alert.signatureEvidence.hit = false;
  alert.mlEvidence.recordPresent = false;
  alert.mlEvidence.evidenceAvailable = false;
  alert.mlEvidence.predictionStatus = 'missing_record';
  assert.equal(getDetectorStatePresentation(alert).key, 'ml_missing');
});

test('Infiltration ML limitation is explicit', () => {
  const alert = baseAlert();
  alert.signatureEvidence.attackType = 'Infiltration';
  alert.mlEvidence.predictedAttackType = 'Benign';
  const state = getDetectorStatePresentation(alert);
  assert.equal(state.key, 'infiltration_ml_limitation');
  assert.match(state.explanation, /signature evidence is retained/i);
  assert.match(state.explanation, /analyst review is required/i);
  assert.doesNotMatch(state.explanation, /authoritative|correct|ground truth/i);
});

test('score-derived fusion band is not presented as generic confidence', () => {
  const source = fs.readFileSync(
    path.join(dashboardRoot, 'src', 'components', 'automated-evidence', 'AutomatedDetectionEvidence.tsx'),
    'utf8'
  );
  assert.match(source, /Detection score band/);
  assert.match(source, /Score-derived category; not model confidence\./);
  assert.doesNotMatch(source, />Confidence level</);
});

test('generic investigation guidance is explicitly separate from TreeSHAP attribution', () => {
  const source = fs.readFileSync(
    path.join(dashboardRoot, 'src', 'components', 'InvestigationsPanel.tsx'),
    'utf8'
  );
  assert.match(source, /General Investigation Context/);
  assert.match(source, /General domain context only; not model attribution/);
  assert.match(source, /TreeSHAP above shows the feature-level model explanation/);
  assert.doesNotMatch(source, /<h3>Feature Interpretation<\/h3>/);
});

test('supporting SHAP array rejects opposing direction', () => {
  const alert = analystAlertWithAvailableExplanation();
  alert.mlEvidence.explanation.topSupportingFeatures[0].direction = 'opposes_prediction';
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('opposing SHAP array rejects supporting direction', () => {
  const alert = analystAlertWithAvailableExplanation();
  alert.mlEvidence.explanation.topOpposingFeatures[0].direction = 'supports_prediction';
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('supporting SHAP array rejects negative contribution', () => {
  const alert = analystAlertWithAvailableExplanation();
  alert.mlEvidence.explanation.topSupportingFeatures[0].shapContribution = -0.1;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('opposing SHAP array rejects positive contribution', () => {
  const alert = analystAlertWithAvailableExplanation();
  alert.mlEvidence.explanation.topOpposingFeatures[0].shapContribution = 0.1;
  assert.equal(validateAnalystAlert(alert).valid, false);
});

test('no-evidence state does not claim ground truth', () => {
  const alert = baseAlert();
  alert.signatureEvidence.hit = false;
  alert.mlEvidence.predictedAttackType = 'Benign';
  alert.automatedDetection.detectorState = 'no_detection_evidence';
  assert.match(getDetectorStatePresentation(alert).explanation, /not ground truth/i);
});

test('unavailable ML does not become Benign', () => {
  const ml = clone(baseAlert().mlEvidence);
  ml.evidenceAvailable = false;
  ml.predictionStatus = 'unavailable';
  ml.predictedAttackType = null;
  const state = getMlAvailabilityPresentation(ml);
  assert.equal(state.key, 'unavailable');
  assert.match(state.explanation, /does not mean.*benign/i);
});

test('available ML prediction and confidence format correctly', () => {
  const ml = baseAlert().mlEvidence;
  assert.equal(getMlAvailabilityPresentation(ml).key, 'available');
  assert.equal(formatModelConfidence(ml.modelConfidence), '91.3%');
});

test('model confidence wording rejects certainty and risk semantics', () => {
  assert.match(ML_CONFIDENCE_HELPER_TEXT, /uncalibrated/i);
  assert.match(ML_CONFIDENCE_HELPER_TEXT, /not certainty or threat risk/i);
});

test('prediction margin is preserved and explained as probability difference', () => {
  const value = 0.866;
  assert.equal(formatPredictionMargin(value), '86.6 percentage points');
  assert.match(PREDICTION_MARGIN_HELPER_TEXT, /highest and second-highest class probability/i);
  assert.equal(value, 0.866);
});

test('SHAP supporting values remain positive', () => {
  assert.ok(baseAlert().mlEvidence.explanation.topSupportingFeatures.every((item) => item.shapContribution > 0));
});

test('SHAP opposing values remain negative', () => {
  assert.ok(baseAlert().mlEvidence.explanation.topOpposingFeatures.every((item) => item.shapContribution < 0));
});

test('SHAP numeric contributions are not modified by visual normalization', () => {
  const source = baseAlert().mlEvidence.explanation.topSupportingFeatures;
  const normalized = normalizeShapWidths(source);
  assert.deepEqual(normalized.map((item) => item.shapContribution), source.map((item) => item.shapContribution));
});

test('SHAP visual normalization does not mutate source features', () => {
  const source = baseAlert().mlEvidence.explanation.topSupportingFeatures;
  const before = clone(source);
  normalizeShapWidths(source);
  assert.deepEqual(source, before);
});

test('zero SHAP contribution produces a zero-width bar', () => {
  assert.equal(normalizeShapWidths([{ shapContribution: 0 }])[0].visualWidth, 0);
  assert.equal(formatSignedShap(0), '0.0000');
});

test('all-zero SHAP contribution set remains finite', () => {
  const result = normalizeShapWidths([{ shapContribution: 0 }, { shapContribution: -0 }]);
  assert.deepEqual(result.map((item) => item.visualWidth), [0, 0]);
});

test('very different SHAP magnitudes normalize only visual width', () => {
  const result = normalizeShapWidths([{ shapContribution: 100 }, { shapContribution: -1 }]);
  assert.deepEqual(result.map((item) => item.visualWidth), [100, 1]);
});

test('non-finite SHAP input cannot create NaN CSS width', () => {
  const result = normalizeShapWidths([{ shapContribution: Number.NaN }, { shapContribution: Infinity }]);
  assert.ok(result.every((item) => Number.isFinite(item.visualWidth) && item.visualWidth === 0));
});

test('available SHAP presentation names the predicted class', () => {
  const presentation = getTreeShapPresentation(baseAlert().mlEvidence);
  assert.equal(presentation.available, true);
  assert.match(presentation.title, /DoS prediction/);
  assert.match(SHAP_HELPER_TEXT, /raw model margin/i);
  assert.match(SHAP_NON_CAUSAL_TEXT, /not probability changes, risk points, or causal effects/i);
});

test('unavailable SHAP reason is shown', () => {
  const ml = clone(baseAlert().mlEvidence);
  ml.explanation = { status: 'unavailable', reason: 'additivity_check_failed' };
  const presentation = getTreeShapPresentation(ml);
  assert.equal(presentation.available, false);
  assert.match(presentation.detail, /additivity validation failed/i);
  assert.match(formatEvidenceReason('tree_shap_generation_failed'), /generation failed/i);
});

test('positive Benign SHAP means support for Benign, not threat increase', () => {
  const label = shapDirectionLabel('supports_prediction', 'Benign');
  assert.equal(label, 'Supports Benign prediction');
  assert.doesNotMatch(label, /threat|malicious|risk/i);
});

test('supporting and opposing groups use one relative visual scale', () => {
  const explanation = baseAlert().mlEvidence.explanation;
  const result = normalizeShapGroups(explanation.topSupportingFeatures, explanation.topOpposingFeatures);
  assert.equal(result.supporting[0].visualWidth, 100);
  assert.equal(result.opposing[0].visualWidth, 32);
});

test('feature values format safely', () => {
  assert.equal(formatFeatureValue(null), 'N/A');
  assert.equal(formatFeatureValue(Number.NaN), 'Invalid value');
  assert.match(formatFeatureValue(12_000_000), /e\+/i);
});

test('advanced provenance hash is shortened visually but preserved', () => {
  const hash = baseAlert().mlEvidence.modelProvenance.modelSha256;
  const display = shortenHash(hash);
  assert.ok(display.length < hash.length);
  assert.equal(baseAlert().mlEvidence.modelProvenance.modelSha256, hash);
});

test('Detection Score remains unchanged after all display helpers', () => {
  const alert = baseAlert();
  const original = alert.automatedDetection.detectionScore;
  getDetectorStatePresentation(alert);
  normalizeShapGroups(alert.mlEvidence.explanation.topSupportingFeatures, alert.mlEvidence.explanation.topOpposingFeatures);
  assert.equal(alert.automatedDetection.detectionScore, original);
});

test('Operational Priority remains unchanged after all display helpers', () => {
  const alert = baseAlert();
  const original = alert.adaptation.operationalPriorityScore;
  getTreeShapPresentation(alert.mlEvidence);
  formatModelConfidence(alert.mlEvidence.modelConfidence);
  assert.equal(alert.adaptation.operationalPriorityScore, original);
});

test('scoring and sorting helpers do not import SHAP display utilities', () => {
  ['src/utils/alertFilters.ts', 'src/utils/feedback.ts'].forEach((relativePath) => {
    const source = fs.readFileSync(path.join(dashboardRoot, relativePath), 'utf8');
    assert.doesNotMatch(source, /automatedEvidence/);
  });
});

test('new automated evidence components consume canonical AnalystAlertV1', () => {
  const componentDir = path.join(dashboardRoot, 'src', 'components', 'automated-evidence');
  const sources = fs.readdirSync(componentDir)
    .filter((name) => name.endsWith('.tsx'))
    .map((name) => fs.readFileSync(path.join(componentDir, name), 'utf8'))
    .join('\n');
  assert.match(sources, /AnalystAlertV1/);
  assert.doesNotMatch(sources, /fusionRiskScore|currentRiskScore|baseRiskScore/);
});

test('analyst artifact still passes Stage 5B validation', () => {
  assert.deepEqual(validateAnalystArtifact(analystArtifact), { valid: true, errors: [] });
});

test('analyst operational data still contains no ground-truth fields', () => {
  assert.deepEqual(findForbiddenGroundTruthPaths(analystArtifact), []);
  assert.equal(analystArtifact.summary.groundTruthFieldCount, 0);
});

test('formal analyst and demonstration artifacts remain separate', () => {
  assert.equal(analystArtifact.artifactType, 'analyst_operational_data');
  assert.equal(demoArtifact.artifactType, 'demonstration_scenarios');
  assert.notEqual(analystArtifact.artifactType, demoArtifact.artifactType);
});
