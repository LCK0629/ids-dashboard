const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const {
  calculateBaseRiskScore,
  calculateMlThreatEvidenceScore,
  fuseAlert,
  fuseAlerts,
  getMlEvidenceState,
  loadJsonFile,
} = require('../core/fusion-engine');

const repoRoot = path.resolve(__dirname, '..', '..');

function signatureRecord(overrides = {}) {
  return {
    id: 'AL-TEST',
    signatureHit: false,
    signatureId: null,
    signatureAttackType: null,
    signatureSeverity: null,
    signatureEvidence: 'No flow-based signature matched.',
    ...overrides,
  };
}

function mlRecord(overrides = {}) {
  return {
    id: 'AL-TEST',
    predictionStatus: 'available',
    predictedClassIndex: 5,
    predictedAttackType: 'Web Attack',
    modelConfidence: 0.9,
    classProbabilities: {
      Benign: 0.08,
      Botnet: 0.01,
      'Brute Force': 0.005,
      DDoS: 0.002,
      DoS: 0.003,
      'Web Attack': 0.9,
    },
    secondBestClass: 'Benign',
    predictionMargin: 0.82,
    modelProvenance: { modelSha256: 'test-model-sha' },
    mlExplanation: {
      status: 'available',
      method: 'xgboost_native_treeshap_pred_contribs',
      outputSpace: 'raw_margin',
      topSupportingFeatures: [{ featureName: 'Dst Port', shapContribution: 1.5 }],
    },
    baseRiskScore: 100,
    ...overrides,
  };
}

test('new-format available ML record is valid evidence', () => {
  const state = getMlEvidenceState(mlRecord());

  assert.equal(state.mlRecordPresent, true);
  assert.equal(state.mlPredictionStatus, 'available');
  assert.equal(state.mlEvidenceAvailable, true);
  assert.equal(state.mlSchemaMode, 'new');
});

test('predictionStatus unavailable is not valid ML evidence', () => {
  const state = getMlEvidenceState(mlRecord({
    predictionStatus: 'unavailable',
    predictedAttackType: null,
    modelConfidence: null,
    failureReason: 'invalid_numeric_feature_values',
  }));

  assert.equal(state.mlRecordPresent, true);
  assert.equal(state.mlEvidenceAvailable, false);
  assert.equal(state.mlFailureReason, 'invalid_numeric_feature_values');
});

test('malformed ML record is not valid evidence', () => {
  const state = getMlEvidenceState(mlRecord({ modelConfidence: 'not-a-number' }));

  assert.equal(state.mlEvidenceAvailable, false);
  assert.equal(state.mlSchemaMode, 'malformed');
});

test('legacy ML record without predictionStatus remains explicitly compatible', () => {
  const legacyRecord = {
    id: 'AL-TEST',
    predictedAttackType: 'DoS',
    modelConfidence: 0.84,
    baseRiskScore: 84,
  };
  const state = getMlEvidenceState(legacyRecord);

  assert.equal(state.mlEvidenceAvailable, true);
  assert.equal(state.mlPredictionStatus, 'legacy_available');
  assert.equal(state.mlSchemaMode, 'legacy');
});

test('no ML record and unavailable ML record are distinguishable', () => {
  const noRecord = fuseAlert(signatureRecord(), null);
  const unavailable = fuseAlert(signatureRecord(), mlRecord({
    predictionStatus: 'unavailable',
    predictedAttackType: null,
    modelConfidence: null,
    failureReason: 'missing_or_invalid_alert_id',
  }));

  assert.equal(noRecord.mlRecordPresent, false);
  assert.equal(noRecord.mlPredictionStatus, 'missing_record');
  assert.equal(noRecord.fusionDecision, 'LOW_RISK_NO_DETECTION_INPUT');
  assert.equal(unavailable.mlRecordPresent, true);
  assert.equal(unavailable.mlPredictionStatus, 'unavailable');
  assert.equal(unavailable.fusionDecision, 'LOW_RISK_ML_UNAVAILABLE');
});

test('high-confidence Benign does not become high threat evidence', () => {
  const record = mlRecord({
    predictedClassIndex: 0,
    predictedAttackType: 'Benign',
    modelConfidence: 0.9987,
    baseRiskScore: 100,
  });

  assert.equal(calculateMlThreatEvidenceScore(record), 0);
  assert.equal(calculateBaseRiskScore(record), 0);
});

test('non-Benign threat evidence derives from confidence', () => {
  assert.equal(calculateMlThreatEvidenceScore(mlRecord({ modelConfidence: 0.864 })), 86);
});

test('Stage 3 legacy baseRiskScore cannot override corrected Stage 4 semantics', () => {
  const record = mlRecord({
    predictedAttackType: 'Benign',
    modelConfidence: 0.99,
    baseRiskScore: 100,
  });
  const fused = fuseAlert(signatureRecord(), record);

  assert.equal(fused.mlLegacyBaseRiskScore, 100);
  assert.equal(fused.mlThreatEvidenceScore, 1);
  assert.equal(fused.baseRiskScore, 1);
  assert.equal(fused.fusionRiskScore, 1);
});

test('unavailable ML plus signature hit follows safe signature path', () => {
  const fused = fuseAlert(
    signatureRecord({
      signatureHit: true,
      signatureId: 'SIG-DOS',
      signatureAttackType: 'DoS',
      signatureSeverity: 'High',
    }),
    mlRecord({
      predictionStatus: 'unavailable',
      predictedAttackType: null,
      modelConfidence: null,
      failureReason: 'missing_required_feature_columns',
    })
  );

  assert.equal(fused.fusionDecision, 'SIGNATURE_ONLY_ML_UNAVAILABLE');
  assert.equal(fused.fusionRiskScore, 80);
  assert.equal(fused.requiresAnalystReview, true);
});

test('unavailable ML plus no signature hit does not invent threat', () => {
  const fused = fuseAlert(
    signatureRecord(),
    mlRecord({
      predictionStatus: 'unavailable',
      predictedAttackType: null,
      modelConfidence: null,
      failureReason: 'duplicate_alert_id',
    })
  );

  assert.equal(fused.fusionDecision, 'LOW_RISK_ML_UNAVAILABLE');
  assert.equal(fused.fusionRiskScore, 0);
  assert.equal(fused.requiresAnalystReview, false);
});

test('Infiltration signature remains protected', () => {
  const fused = fuseAlert(
    signatureRecord({
      signatureHit: true,
      signatureId: 'SIG-INFILTRATION',
      signatureAttackType: 'Infiltration',
      signatureSeverity: 'Critical',
    }),
    mlRecord({
      predictedClassIndex: 0,
      predictedAttackType: 'Benign',
      modelConfidence: 0.999,
      baseRiskScore: 100,
    })
  );

  assert.equal(fused.fusionDecision, 'SIGNATURE_ONLY_ML_LIMITATION');
  assert.equal(fused.fusionAttackType, 'Infiltration');
  assert.equal(fused.fusionRiskScore, 95);
  assert.equal(fused.requiresAnalystReview, true);
});

test('Infiltration plus ML Benign does not inflate risk through legacy baseRiskScore', () => {
  const fused = fuseAlert(
    signatureRecord({
      signatureHit: true,
      signatureAttackType: 'Infiltration',
      signatureSeverity: 'Critical',
    }),
    mlRecord({
      predictedAttackType: 'Benign',
      modelConfidence: 1,
      baseRiskScore: 100,
    })
  );

  assert.equal(fused.mlThreatEvidenceScore, 0);
  assert.equal(fused.fusionRiskScore, 95);
});

test('classProbabilities pass through unchanged', () => {
  const ml = mlRecord();
  assert.deepEqual(fuseAlert(signatureRecord(), ml).classProbabilities, ml.classProbabilities);
});

test('predictionMargin passes through unchanged', () => {
  const ml = mlRecord({ predictionMargin: 0.55 });
  assert.equal(fuseAlert(signatureRecord(), ml).predictionMargin, 0.55);
});

test('modelProvenance passes through unchanged', () => {
  const ml = mlRecord({ modelProvenance: { modelSha256: 'abc', xgboostVersion: '3.3.0' } });
  assert.deepEqual(fuseAlert(signatureRecord(), ml).modelProvenance, ml.modelProvenance);
});

test('available mlExplanation passes through unchanged', () => {
  const ml = mlRecord();
  assert.deepEqual(fuseAlert(signatureRecord(), ml).mlExplanation, ml.mlExplanation);
});

test('unavailable mlExplanation passes through unchanged', () => {
  const explanation = { status: 'unavailable', reason: 'prediction_unavailable' };
  const ml = mlRecord({
    predictionStatus: 'unavailable',
    predictedAttackType: null,
    modelConfidence: null,
    mlExplanation: explanation,
  });

  assert.deepEqual(fuseAlert(signatureRecord(), ml).mlExplanation, explanation);
});

test('SHAP fields have zero influence on fusionRiskScore', () => {
  const base = fuseAlert(signatureRecord(), mlRecord());
  const changedShap = fuseAlert(signatureRecord(), mlRecord({
    mlExplanation: {
      status: 'available',
      outputSpace: 'raw_margin',
      topSupportingFeatures: [{ featureName: 'Anything', shapContribution: 9999 }],
      topOpposingFeatures: [{ featureName: 'Other', shapContribution: -9999 }],
    },
  }));

  assert.equal(changedShap.fusionRiskScore, base.fusionRiskScore);
});

test('changing SHAP values only does not change fusionDecision', () => {
  const base = fuseAlert(signatureRecord(), mlRecord());
  const changedShap = fuseAlert(signatureRecord(), mlRecord({
    mlExplanation: { status: 'available', rawModelMargin: -12345 },
  }));

  assert.equal(changedShap.fusionDecision, base.fusionDecision);
});

test('ground truth is not consumed by fuseAlert', () => {
  const withoutTruth = fuseAlert(signatureRecord(), mlRecord());
  const withTruth = fuseAlert(
    { ...signatureRecord(), groundTruth: 'benign', trueAttackType: 'Benign' },
    { ...mlRecord(), groundTruth: 'malicious', rawLabel: 'DoS' }
  );

  assert.equal(withTruth.fusionDecision, withoutTruth.fusionDecision);
  assert.equal(withTruth.fusionRiskScore, withoutTruth.fusionRiskScore);
});

test('alignment summary separates Stage 3 records from available predictions', () => {
  const result = fuseAlerts(
    [signatureRecord({ id: 'AL-1' }), signatureRecord({ id: 'AL-2' })],
    [
      mlRecord({ id: 'AL-1' }),
      mlRecord({
        id: 'AL-2',
        predictionStatus: 'unavailable',
        predictedAttackType: null,
        modelConfidence: null,
      }),
      mlRecord({ id: 'AL-OUT' }),
    ]
  );

  assert.equal(result.idAlignmentSummary.stage3RecordCount, 3);
  assert.equal(result.idAlignmentSummary.stage3AvailablePredictionCount, 2);
  assert.equal(result.idAlignmentSummary.stage3UnavailablePredictionCount, 1);
  assert.equal(result.idAlignmentSummary.matchedStage3RecordCount, 2);
  assert.equal(result.idAlignmentSummary.matchedAvailablePredictionCount, 1);
  assert.equal(result.idAlignmentSummary.matchedUnavailablePredictionCount, 1);
});

test('sorting still uses fusionRiskScore, review semantics, and id', () => {
  const result = fuseAlerts(
    [
      signatureRecord({ id: 'AL-2', signatureHit: true, signatureAttackType: 'DoS', signatureSeverity: 'High' }),
      signatureRecord({ id: 'AL-1' }),
      signatureRecord({ id: 'AL-3' }),
    ],
    [
      mlRecord({ id: 'AL-1', predictedAttackType: 'Web Attack', modelConfidence: 0.8 }),
      mlRecord({ id: 'AL-3', predictedAttackType: 'Benign', modelConfidence: 1 }),
    ]
  );

  assert.deepEqual(result.fusedAlerts.map((alert) => alert.id), ['AL-2', 'AL-1', 'AL-3']);
});

test('current legacy Stage 4 sample remains runnable', () => {
  const signatureOutput = loadJsonFile(path.join(repoRoot, 'stage-2', 'data', 'signature-output.sample.json'));
  const mlPredictions = loadJsonFile(path.join(repoRoot, 'stage-3', 'outputs', 'ml-predictions.sample.json'));
  const result = fuseAlerts(signatureOutput, mlPredictions);

  assert.equal(result.fusedAlerts.length, 1000);
  assert.equal(result.idAlignmentSummary.stage3RecordCount, 996);
  assert.equal(result.idAlignmentSummary.stage3AvailablePredictionCount, 996);
});

test('full regenerated Stage 3 schema is runnable', () => {
  const signatureOutput = loadJsonFile(path.join(repoRoot, 'stage-2', 'data', 'signature-output.sample.json'));
  const mlPredictions = loadJsonFile(path.join(repoRoot, 'stage-3', 'outputs', 'ml-predictions.regenerated.json'));
  const result = fuseAlerts(signatureOutput, mlPredictions);

  assert.equal(result.fusedAlerts.length, 1000);
  assert.equal(result.idAlignmentSummary.stage3RecordCount, 1000);
  assert.equal(result.idAlignmentSummary.stage3AvailablePredictionCount, 996);
  assert.equal(result.idAlignmentSummary.stage3UnavailablePredictionCount, 4);
});

test('Stage 3 to Stage 4 ID joining remains deterministic', () => {
  const result = fuseAlerts(
    [signatureRecord({ id: 'AL-10' }), signatureRecord({ id: 'AL-2' })],
    [mlRecord({ id: 'AL-2' }), mlRecord({ id: 'AL-10' })]
  );

  assert.deepEqual(result.fusedAlerts.map((alert) => alert.id), ['AL-10', 'AL-2']);
  assert.equal(result.idAlignmentSummary.matchedIdCount, 2);
});

test('run-fusion-demo supports explicit full-schema ML prediction input', () => {
  const scriptPath = path.join(repoRoot, 'stage-4', 'scripts', 'run-fusion-demo.js');
  const regeneratedPath = path.join(repoRoot, 'stage-3', 'outputs', 'ml-predictions.regenerated.json');
  const output = execFileSync(process.execPath, [scriptPath, '--ml-predictions', regeneratedPath], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  assert.match(output, /ML predictions loaded: 1000/);
  assert.match(output, /ML evidence available: 996/);
  assert.match(output, /ML evidence unavailable: 4/);
});
