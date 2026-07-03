const fs = require('fs');

function loadJsonFile(filePath, fallback = null) {
  if (!fs.existsSync(filePath)) {
    if (fallback !== null) {
      return fallback;
    }
    throw new Error(`JSON file not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function clampScore(score) {
  const numericScore = Number(score);
  if (Number.isNaN(numericScore)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function severityToScore(severity, signatureHit = false) {
  const scores = {
    Low: 40,
    Medium: 60,
    High: 80,
    Critical: 95,
  };

  if (severity && scores[severity] !== undefined) {
    return scores[severity];
  }

  return signatureHit ? 50 : 0;
}

function getFusionConfidenceLevel(score) {
  const riskScore = clampScore(score);
  if (riskScore >= 90) {
    return 'Critical';
  }
  if (riskScore >= 70) {
    return 'High';
  }
  if (riskScore >= 40) {
    return 'Medium';
  }
  return 'Low';
}

function calculateBaseRiskScore(mlPrediction) {
  if (!mlPrediction) {
    return 0;
  }

  if (mlPrediction.baseRiskScore !== undefined && mlPrediction.baseRiskScore !== null) {
    return clampScore(mlPrediction.baseRiskScore);
  }

  const confidenceScore = Math.round(Number(mlPrediction.modelConfidence || 0) * 100);
  if (mlPrediction.predictedAttackType === 'Benign') {
    return clampScore(100 - confidenceScore);
  }

  return clampScore(confidenceScore);
}

function buildBaseAlert(id, signatureRecord, mlPrediction) {
  return {
    id,
    signatureHit: Boolean(signatureRecord && signatureRecord.signatureHit),
    signatureId: signatureRecord ? signatureRecord.signatureId || null : null,
    signatureAttackType: signatureRecord ? signatureRecord.signatureAttackType || null : null,
    signatureSeverity: signatureRecord ? signatureRecord.signatureSeverity || null : null,
    signatureEvidence: signatureRecord ? signatureRecord.signatureEvidence || 'No signature evidence available.' : 'No signature record was available for this ID.',
    mlPredictedAttackType: mlPrediction ? mlPrediction.predictedAttackType || null : null,
    modelConfidence: mlPrediction && mlPrediction.modelConfidence !== undefined ? Number(mlPrediction.modelConfidence) : null,
    baseRiskScore: calculateBaseRiskScore(mlPrediction),
  };
}

function evidenceText(parts) {
  return parts.filter(Boolean).join(' ');
}

function fuseAlert(signatureRecord = null, mlPrediction = null) {
  const id = (signatureRecord && signatureRecord.id) || (mlPrediction && mlPrediction.id);
  const baseAlert = buildBaseAlert(id, signatureRecord, mlPrediction);
  const signatureSeverityScore = severityToScore(baseAlert.signatureSeverity, baseAlert.signatureHit);
  const hasMlPrediction = Boolean(mlPrediction);
  const mlAttackType = baseAlert.mlPredictedAttackType;
  const signatureAttackType = baseAlert.signatureAttackType;
  const modelConfidence = baseAlert.modelConfidence === null ? 0 : baseAlert.modelConfidence;

  let fusionAttackType = 'Benign';
  let fusionDecision = 'LOW_RISK_BENIGN';
  let fusionRiskScore = 0;
  let requiresAnalystReview = false;
  let fusionEvidence = '';

  if (baseAlert.signatureHit && signatureAttackType === 'Infiltration') {
    fusionAttackType = 'Infiltration';
    fusionDecision = 'SIGNATURE_ONLY_ML_LIMITATION';
    fusionRiskScore = clampScore(Math.max(signatureSeverityScore, baseAlert.baseRiskScore));
    requiresAnalystReview = true;
    fusionEvidence = evidenceText([
      'Stage 2 signature evidence indicates Infiltration.',
      hasMlPrediction
        ? `Stage 3 predicted ${mlAttackType || 'no class'} with confidence ${modelConfidence.toFixed(3)}.`
        : 'No Stage 3 ML prediction was available for this ID.',
      'The current Stage 3 ML artifacts do not include Infiltration, so the signature evidence is retained instead of downgrading the alert.',
    ]);
  } else if (baseAlert.signatureHit && hasMlPrediction && signatureAttackType === mlAttackType) {
    fusionAttackType = signatureAttackType;
    fusionDecision = 'SIGNATURE_ML_AGREE';
    fusionRiskScore = clampScore(baseAlert.baseRiskScore + 10);
    requiresAnalystReview = fusionRiskScore >= 90;
    fusionEvidence = evidenceText([
      'Signature and ML agree.',
      `Signature matched ${baseAlert.signatureId || 'a known rule'}.`,
      `ML predicted the same class with confidence ${modelConfidence.toFixed(3)}.`,
    ]);
  } else if (baseAlert.signatureHit && hasMlPrediction && mlAttackType === 'Benign') {
    fusionAttackType = signatureAttackType;
    fusionDecision = 'SIGNATURE_ONLY_ML_BENIGN';
    fusionRiskScore = clampScore(signatureSeverityScore + 10);
    requiresAnalystReview = true;
    fusionEvidence = evidenceText([
      'Signature rule matched known attack-like behavior.',
      'ML predicted Benign.',
      'The alert is retained because known-pattern evidence exists.',
    ]);
  } else if (baseAlert.signatureHit && hasMlPrediction && signatureAttackType !== mlAttackType) {
    fusionAttackType = signatureAttackType;
    fusionDecision = 'SIGNATURE_ML_DISAGREE';
    fusionRiskScore = clampScore(Math.max(baseAlert.baseRiskScore, signatureSeverityScore) + 5);
    requiresAnalystReview = true;
    fusionEvidence = evidenceText([
      `Signature evidence indicates ${signatureAttackType}.`,
      `ML predicts ${mlAttackType}.`,
      'This conflicting evidence should be reviewed by an analyst.',
    ]);
  } else if (baseAlert.signatureHit && !hasMlPrediction) {
    fusionAttackType = signatureAttackType;
    fusionDecision = 'SIGNATURE_ONLY_NO_ML';
    fusionRiskScore = clampScore(signatureSeverityScore);
    requiresAnalystReview = true;
    fusionEvidence = evidenceText([
      'Signature evidence exists.',
      'No ML prediction was available for this ID.',
      'Risk is based on signature severity.',
    ]);
  } else if (!signatureRecord && hasMlPrediction) {
    fusionAttackType = mlAttackType || 'Unknown';
    fusionDecision = 'ML_ONLY_NO_SIGNATURE_RECORD';
    fusionRiskScore = clampScore(baseAlert.baseRiskScore);
    requiresAnalystReview = fusionRiskScore >= 70;
    fusionEvidence = evidenceText([
      'ML prediction exists.',
      'No signature record was available for this ID.',
      'Risk is based on ML confidence.',
    ]);
  } else if (!baseAlert.signatureHit && hasMlPrediction && mlAttackType !== 'Benign' && modelConfidence >= 0.8) {
    fusionAttackType = mlAttackType;
    fusionDecision = 'ML_ONLY_HIGH_CONFIDENCE';
    fusionRiskScore = clampScore(baseAlert.baseRiskScore);
    requiresAnalystReview = fusionRiskScore >= 70;
    fusionEvidence = evidenceText([
      'No signature rule matched.',
      'ML detected an attack-like flow with high confidence.',
      'This may represent a pattern not covered by current signature rules.',
    ]);
  } else if (!baseAlert.signatureHit && hasMlPrediction && mlAttackType !== 'Benign' && modelConfidence >= 0.5) {
    fusionAttackType = mlAttackType;
    fusionDecision = 'ML_ONLY_MEDIUM_CONFIDENCE';
    fusionRiskScore = clampScore(baseAlert.baseRiskScore - 10);
    requiresAnalystReview = fusionRiskScore >= 60;
    fusionEvidence = evidenceText([
      'ML produced a non-benign prediction.',
      'No signature evidence supports it.',
      'Risk is reduced slightly due to lack of signature evidence.',
    ]);
  } else if (!baseAlert.signatureHit && hasMlPrediction && mlAttackType === 'Benign') {
    fusionAttackType = 'Benign';
    fusionDecision = 'LOW_RISK_BENIGN';
    fusionRiskScore = clampScore(100 - Math.round(modelConfidence * 100));
    requiresAnalystReview = false;
    fusionEvidence = evidenceText([
      'No signature evidence.',
      'ML predicts Benign.',
      'Alert is low priority.',
    ]);
  } else {
    fusionAttackType = 'Benign';
    fusionDecision = 'LOW_RISK_NO_DETECTION_INPUT';
    fusionRiskScore = 0;
    requiresAnalystReview = false;
    fusionEvidence = 'No signature rule matched and no ML prediction was available for this ID. Alert is kept as low priority.';
  }

  return {
    ...baseAlert,
    fusionAttackType,
    fusionRiskScore: clampScore(fusionRiskScore),
    fusionDecision,
    fusionEvidence,
    requiresAnalystReview,
    fusionConfidenceLevel: getFusionConfidenceLevel(fusionRiskScore),
  };
}

function indexById(records) {
  const index = new Map();
  for (const record of records || []) {
    if (record && record.id !== undefined && record.id !== null) {
      index.set(String(record.id), record);
    }
  }
  return index;
}

function fuseAlerts(signatureRecords, mlPredictions) {
  const signatureById = indexById(signatureRecords);
  const mlById = indexById(mlPredictions);
  const ids = new Set([...signatureById.keys(), ...mlById.keys()]);

  return [...ids]
    .map((id) => fuseAlert(signatureById.get(id) || null, mlById.get(id) || null))
    .sort((a, b) => {
      if (b.fusionRiskScore !== a.fusionRiskScore) {
        return b.fusionRiskScore - a.fusionRiskScore;
      }
      if (a.requiresAnalystReview !== b.requiresAnalystReview) {
        return a.requiresAnalystReview ? -1 : 1;
      }
      return String(a.id).localeCompare(String(b.id));
    });
}

function incrementCounter(counter, key) {
  const safeKey = key || 'Unknown';
  counter[safeKey] = (counter[safeKey] || 0) + 1;
}

function summariseFusionResults(fusedAlerts, groundTruth = null) {
  const summary = {
    totalFusedAlerts: fusedAlerts.length,
    countByFusionDecision: {},
    countByFusionConfidenceLevel: {},
    countRequiringAnalystReview: 0,
    averageFusionRiskScore: 0,
    maxFusionRiskScore: 0,
    minFusionRiskScore: 0,
    countByFusionAttackType: {},
    signatureMlAgreementCount: 0,
    signatureMlDisagreementCount: 0,
    mlOnlyAlertCount: 0,
    signatureOnlyAlertCount: 0,
    notes: [
      'Stage 4 is a prototype fusion evaluation, not final IDS performance.',
      'Ground truth is joined only after fusion for evaluation.',
      'Current Stage 3 ML artifacts do not include Infiltration; Stage 4 retains Infiltration signature alerts.',
    ],
  };

  const scores = fusedAlerts.map((alert) => alert.fusionRiskScore);
  summary.averageFusionRiskScore = scores.length
    ? Number((scores.reduce((total, score) => total + score, 0) / scores.length).toFixed(2))
    : 0;
  summary.maxFusionRiskScore = scores.length ? Math.max(...scores) : 0;
  summary.minFusionRiskScore = scores.length ? Math.min(...scores) : 0;

  for (const alert of fusedAlerts) {
    incrementCounter(summary.countByFusionDecision, alert.fusionDecision);
    incrementCounter(summary.countByFusionConfidenceLevel, alert.fusionConfidenceLevel);
    incrementCounter(summary.countByFusionAttackType, alert.fusionAttackType);
    if (alert.requiresAnalystReview) {
      summary.countRequiringAnalystReview += 1;
    }
    if (alert.fusionDecision === 'SIGNATURE_ML_AGREE') {
      summary.signatureMlAgreementCount += 1;
    }
    if (alert.fusionDecision === 'SIGNATURE_ML_DISAGREE' || alert.fusionDecision === 'SIGNATURE_ONLY_ML_BENIGN') {
      summary.signatureMlDisagreementCount += 1;
    }
    if (alert.fusionDecision.startsWith('ML_ONLY')) {
      summary.mlOnlyAlertCount += 1;
    }
    if (alert.fusionDecision.startsWith('SIGNATURE_ONLY')) {
      summary.signatureOnlyAlertCount += 1;
    }
  }

  if (groundTruth) {
    summary.groundTruthEvaluation = {
      countByTrueAttackType: {},
      countByFusionAttackType: { ...summary.countByFusionAttackType },
      matchingFusionAttackTypeCount: 0,
      evaluatedAlertCount: 0,
      simpleFusionAccuracy: 0,
      falsePositiveStyleCount: 0,
      falseNegativeStyleCount: 0,
    };

    for (const alert of fusedAlerts) {
      const truth = groundTruth[String(alert.id)];
      if (!truth) {
        continue;
      }
      const trueAttackType = truth.mappedAttackType || truth.trueAttackType || 'Unknown';
      const groundTruthLabel = truth.groundTruth || (trueAttackType === 'Benign' ? 'benign' : 'malicious');
      summary.groundTruthEvaluation.evaluatedAlertCount += 1;
      incrementCounter(summary.groundTruthEvaluation.countByTrueAttackType, trueAttackType);
      if (alert.fusionAttackType === trueAttackType) {
        summary.groundTruthEvaluation.matchingFusionAttackTypeCount += 1;
      }
      if (groundTruthLabel === 'benign' && alert.fusionAttackType !== 'Benign') {
        summary.groundTruthEvaluation.falsePositiveStyleCount += 1;
      }
      if (groundTruthLabel === 'malicious' && alert.fusionAttackType === 'Benign') {
        summary.groundTruthEvaluation.falseNegativeStyleCount += 1;
      }
    }

    const evaluated = summary.groundTruthEvaluation.evaluatedAlertCount;
    summary.groundTruthEvaluation.simpleFusionAccuracy = evaluated
      ? Number((summary.groundTruthEvaluation.matchingFusionAttackTypeCount / evaluated).toFixed(4))
      : 0;
  }

  return summary;
}

module.exports = {
  loadJsonFile,
  clampScore,
  severityToScore,
  getFusionConfidenceLevel,
  calculateBaseRiskScore,
  fuseAlert,
  fuseAlerts,
  summariseFusionResults,
};
