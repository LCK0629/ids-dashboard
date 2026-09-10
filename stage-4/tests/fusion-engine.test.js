const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  calculateBaseRiskScore,
  calculateMlThreatEvidenceScore,
  fuseAlert,
  fuseAlertLegacyBaseline,
  fuseAlerts,
  fuseAlertsLegacyBaseline,
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

function withTempDir(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage4-fusion-test-'));
  try {
    return callback(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
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

test('new-format available ML record requires real numeric confidence', () => {
  const invalidConfidenceValues = [
    null,
    undefined,
    '',
    '   ',
    '0.9',
    NaN,
    Infinity,
    -Infinity,
    true,
    false,
  ];

  for (const modelConfidence of invalidConfidenceValues) {
    const state = getMlEvidenceState(mlRecord({ modelConfidence }));
    assert.equal(state.mlRecordPresent, true);
    assert.equal(state.mlPredictionStatus, 'available');
    assert.equal(state.mlEvidenceAvailable, false, `expected invalid confidence ${String(modelConfidence)}`);
    assert.equal(state.mlSchemaMode, 'malformed');
  }
});

test('new-format available ML record requires safe predictedClassIndex', () => {
  for (const predictedClassIndex of [null, undefined, '', '5', 1.5, -1, NaN, Infinity, true]) {
    const state = getMlEvidenceState(mlRecord({ predictedClassIndex }));
    assert.equal(state.mlRecordPresent, true);
    assert.equal(state.mlPredictionStatus, 'available');
    assert.equal(state.mlEvidenceAvailable, false, `expected invalid class index ${String(predictedClassIndex)}`);
    assert.equal(state.mlSchemaMode, 'malformed');
  }
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

test('modelProvenance remains available when ML prediction is unavailable', () => {
  const provenance = { modelSha256: 'abc', xgboostVersion: '3.3.0' };
  const fused = fuseAlert(
    signatureRecord(),
    mlRecord({
      predictionStatus: 'unavailable',
      predictedAttackType: null,
      modelConfidence: null,
      failureReason: 'missing_required_feature_columns',
      modelProvenance: provenance,
    })
  );

  assert.equal(fused.mlEvidenceAvailable, false);
  assert.deepEqual(fused.modelProvenance, provenance);
  assert.equal(fuseAlert(signatureRecord(), null).modelProvenance, null);
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
  const signatureOutput = [
    signatureRecord({ id: 'AL-1', signatureHit: true, signatureAttackType: 'DoS', signatureSeverity: 'High' }),
    signatureRecord({ id: 'AL-2' }),
    signatureRecord({ id: 'AL-3' }),
  ];
  const mlPredictions = [
    mlRecord({ id: 'AL-1', predictedAttackType: 'DoS', modelConfidence: 0.91 }),
    mlRecord({
      id: 'AL-2',
      predictionStatus: 'unavailable',
      predictedAttackType: null,
      modelConfidence: null,
      failureReason: 'invalid_numeric_feature_values',
      modelProvenance: { modelSha256: 'synthetic-test-model' },
      mlExplanation: { status: 'unavailable', reason: 'prediction_unavailable' },
    }),
    mlRecord({ id: 'AL-OUT', predictedAttackType: 'Web Attack', modelConfidence: 0.88 }),
  ];
  const result = fuseAlerts(signatureOutput, mlPredictions);

  assert.equal(result.fusedAlerts.length, 3);
  assert.equal(result.idAlignmentSummary.stage3RecordCount, 3);
  assert.equal(result.idAlignmentSummary.stage3AvailablePredictionCount, 2);
  assert.equal(result.idAlignmentSummary.stage3UnavailablePredictionCount, 1);
  assert.equal(result.idAlignmentSummary.stage3OutOfScopeCount, 1);
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
  withTempDir((directory) => {
    const scriptPath = path.join(repoRoot, 'stage-4', 'scripts', 'run-fusion-demo.js');
    const mlPredictionsPath = path.join(directory, 'ml-predictions.synthetic.json');
    const outputDir = path.join(directory, 'outputs');
    const evaluationDir = path.join(directory, 'evaluation');
    fs.writeFileSync(
      mlPredictionsPath,
      `${JSON.stringify([
        mlRecord({ id: 'AL-0001', predictedAttackType: 'DoS', modelConfidence: 0.91 }),
        mlRecord({
          id: 'AL-0002',
          predictionStatus: 'unavailable',
          predictedAttackType: null,
          modelConfidence: null,
          failureReason: 'invalid_numeric_feature_values',
          mlExplanation: { status: 'unavailable', reason: 'prediction_unavailable' },
        }),
      ], null, 2)}\n`,
      'utf8'
    );

    const output = execFileSync(process.execPath, [
      scriptPath,
      '--ml-predictions',
      mlPredictionsPath,
      '--output-dir',
      outputDir,
      '--evaluation-dir',
      evaluationDir,
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
    });

    assert.match(output, /ML predictions loaded: 2/);
    assert.match(output, /ML evidence available: 1/);
    assert.match(output, /ML evidence unavailable: 1/);
    assert.ok(fs.existsSync(path.join(outputDir, 'fusion-alerts.sample.json')));
    assert.ok(fs.existsSync(path.join(evaluationDir, 'fusion-evaluation-summary.json')));
    assert.ok(fs.existsSync(path.join(evaluationDir, 'ml-evidence-integration-summary.json')));
  });
});

test('legacy baseline reproduces old presence-based unavailable ML-only behaviour', () => {
  const unavailableMl = mlRecord({
    predictionStatus: 'unavailable',
    predictedAttackType: 'DoS',
    modelConfidence: 0.95,
    baseRiskScore: 95,
    failureReason: 'invalid_numeric_feature_values',
  });

  const oldAlert = fuseAlertLegacyBaseline(signatureRecord(), unavailableMl);
  const newAlert = fuseAlert(signatureRecord(), unavailableMl);

  assert.equal(oldAlert.fusionDecision, 'ML_ONLY_HIGH_CONFIDENCE');
  assert.equal(oldAlert.fusionRiskScore, 85);
  assert.equal(newAlert.fusionDecision, 'LOW_RISK_ML_UNAVAILABLE');
  assert.equal(newAlert.fusionRiskScore, 0);
});

test('legacy baseline reproduces old presence-based unavailable ML plus signature behaviour', () => {
  const signature = signatureRecord({
    signatureHit: true,
    signatureId: 'SIG-DOS',
    signatureAttackType: 'DoS',
    signatureSeverity: 'High',
  });
  const unavailableMl = mlRecord({
    predictionStatus: 'unavailable',
    predictedAttackType: 'DoS',
    modelConfidence: 0.95,
    baseRiskScore: 95,
    failureReason: 'invalid_numeric_feature_values',
  });

  const oldAlert = fuseAlertLegacyBaseline(signature, unavailableMl);
  const newAlert = fuseAlert(signature, unavailableMl);

  assert.equal(oldAlert.fusionDecision, 'SIGNATURE_ML_AGREE');
  assert.equal(oldAlert.fusionRiskScore, 100);
  assert.equal(newAlert.fusionDecision, 'SIGNATURE_ONLY_ML_UNAVAILABLE');
  assert.equal(newAlert.fusionRiskScore, 80);
});

test('legacy baseline captures high-confidence Benign baseRiskScore inflation where it affected scoring', () => {
  const signature = signatureRecord({
    signatureHit: true,
    signatureId: 'SIG-INFILTRATION',
    signatureAttackType: 'Infiltration',
    signatureSeverity: 'Critical',
  });
  const benignMl = mlRecord({
    predictedClassIndex: 0,
    predictedAttackType: 'Benign',
    modelConfidence: 0.99,
    baseRiskScore: 100,
  });

  const oldAlert = fuseAlertLegacyBaseline(signature, benignMl);
  const newAlert = fuseAlert(signature, benignMl);

  assert.equal(oldAlert.fusionDecision, 'SIGNATURE_ONLY_ML_LIMITATION');
  assert.equal(oldAlert.fusionRiskScore, 100);
  assert.equal(newAlert.fusionDecision, 'SIGNATURE_ONLY_ML_LIMITATION');
  assert.equal(newAlert.fusionRiskScore, 95);
});

test('legacy baseline comparison remains Stage-2-scoped and deterministic', () => {
  const result = fuseAlertsLegacyBaseline(
    [
      signatureRecord({ id: 'AL-2', signatureHit: true, signatureAttackType: 'DoS', signatureSeverity: 'High' }),
      signatureRecord({ id: 'AL-1' }),
    ],
    [
      mlRecord({ id: 'AL-1', predictionStatus: 'unavailable', predictedAttackType: 'DoS', modelConfidence: 0.9 }),
      mlRecord({ id: 'AL-OUT', predictedAttackType: 'DDoS', modelConfidence: 0.95 }),
    ]
  );

  assert.deepEqual(result.fusedAlerts.map((alert) => alert.id).sort(), ['AL-1', 'AL-2']);
  assert.equal(result.idAlignmentSummary.stage3OutOfScopeCount, 1);
});
