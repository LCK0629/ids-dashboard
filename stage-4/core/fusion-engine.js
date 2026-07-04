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

function buildFlowFeatureSummary(signatureRecord) {
  if (!signatureRecord) {
    return {};
  }

  return {
    protocol: signatureRecord.protocol,
    sourcePort: signatureRecord.sourcePort,
    destinationPort: signatureRecord.destinationPort,
    flowDuration: signatureRecord.flowDuration,
    totalFwdPackets: signatureRecord.totalFwdPackets,
    totalBackwardPackets: signatureRecord.totalBwdPackets,
    totalLengthFwdPackets: signatureRecord.totalLengthFwdPackets,
    totalLengthBwdPackets: signatureRecord.totalLengthBwdPackets,
    flowPacketsPerSecond: signatureRecord.flowPacketsPerSecond,
    flowBytesPerSecond: signatureRecord.flowBytesPerSecond,
    packetLengthMean: signatureRecord.packetLengthMean,
    packetLengthMax: signatureRecord.packetLengthMax,
    fwdPacketLengthMean: signatureRecord.fwdPacketLengthMean,
    flowIatMean: signatureRecord.flowIatMean,
    flowIatStd: signatureRecord.flowIatStd,
    synFlagCount: signatureRecord.synFlagCount,
    ackFlagCount: signatureRecord.ackFlagCount,
    pshFlagCount: signatureRecord.pshFlagCount,
  };
}

function buildBaseAlert(id, signatureRecord, mlPrediction) {
  return {
    id,
    flowFeatureSummary: buildFlowFeatureSummary(signatureRecord),
    signatureHit: Boolean(signatureRecord && signatureRecord.signatureHit),
    signatureId: signatureRecord ? signatureRecord.signatureId || null : null,
    signatureAttackType: signatureRecord ? signatureRecord.signatureAttackType || null : null,
    signatureSeverity: signatureRecord ? signatureRecord.signatureSeverity || null : null,
    signatureSummary: signatureRecord ? signatureRecord.signatureSummary || null : null,
    signaturePlainExplanation: signatureRecord ? signatureRecord.signaturePlainExplanation || null : null,
    matchedConditionsReadable: signatureRecord ? signatureRecord.matchedConditionsReadable || [] : [],
    signatureTechnicalDetails: signatureRecord ? signatureRecord.signatureTechnicalDetails || null : null,
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
    // This case fires only when no Stage 2 signature record exists at all for this id.
    // This is distinct from a record existing with signatureHit=false, which is handled below.
    // It is not normally reachable through the current Stage-2-scoped fuseAlerts() iteration,
    // but is retained for direct fuseAlert() callers and possible future union-mode fusion.
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
    fusionRiskScore = clampScore(Math.max(baseAlert.baseRiskScore - 10, 70));
    requiresAnalystReview = fusionRiskScore >= 70;
    fusionEvidence = evidenceText([
      'ML predicted a non-benign class with high confidence, but no signature rule matched.',
      'The score is slightly discounted because the alert has ML-only evidence.',
    ]);
  } else if (!baseAlert.signatureHit && hasMlPrediction && mlAttackType !== 'Benign' && modelConfidence >= 0.5) {
    fusionAttackType = mlAttackType;
    fusionDecision = 'ML_ONLY_MEDIUM_CONFIDENCE';
    fusionRiskScore = clampScore(Math.max(baseAlert.baseRiskScore - 20, 40));
    requiresAnalystReview = fusionRiskScore >= 60;
    fusionEvidence = evidenceText([
      'ML predicted a non-benign class with medium confidence, but no signature rule matched.',
      'The score is discounted more strongly due to weaker ML-only evidence.',
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

function sortIds(ids) {
  return [...ids].sort((a, b) => String(a).localeCompare(String(b), undefined, { numeric: true }));
}

function getAlignmentWarning(alignmentStatus) {
  if (alignmentStatus === 'WARNING_PARTIAL_OVERLAP') {
    return 'Stage 2 and Stage 3 IDs are only partially aligned. Fusion output remains Stage-2-scoped, but some alerts do not have paired ML evidence.';
  }
  if (alignmentStatus === 'ERROR_LOW_OVERLAP') {
    return 'Stage 2 and Stage 3 IDs have low overlap. This may indicate that ML predictions were generated from a different record source.';
  }
  return null;
}

function getAlignmentStatus(overlapRateAgainstStage2) {
  if (overlapRateAgainstStage2 >= 0.95) {
    return 'OK';
  }
  if (overlapRateAgainstStage2 >= 0.5) {
    return 'WARNING_PARTIAL_OVERLAP';
  }
  return 'ERROR_LOW_OVERLAP';
}

function buildIdAlignmentSummary(signatureById, mlById) {
  const stage2Ids = [...signatureById.keys()];
  const stage3Ids = [...mlById.keys()];
  const matchedIds = stage2Ids.filter((id) => mlById.has(id));
  const stage2OnlyIds = sortIds(stage2Ids.filter((id) => !mlById.has(id)));
  const outOfScopeMlPredictionIds = sortIds(stage3Ids.filter((id) => !signatureById.has(id)));
  const overlapRateAgainstStage2 = safeDivide(matchedIds.length, stage2Ids.length);
  const overlapRateAgainstStage3 = safeDivide(matchedIds.length, stage3Ids.length);
  const alignmentStatus = getAlignmentStatus(overlapRateAgainstStage2);

  return {
    stage2RecordCount: stage2Ids.length,
    stage3PredictionCount: stage3Ids.length,
    matchedIdCount: matchedIds.length,
    stage2OnlyCount: stage2OnlyIds.length,
    stage3OutOfScopeCount: outOfScopeMlPredictionIds.length,
    overlapRateAgainstStage2,
    overlapRateAgainstStage3,
    alignmentStatus,
    alignmentWarning: getAlignmentWarning(alignmentStatus),
    stage2OnlyIdsSample: stage2OnlyIds.slice(0, 50),
    outOfScopeMlPredictionIdsSample: outOfScopeMlPredictionIds.slice(0, 50),
    outOfScopeMlPredictionIds,
  };
}

function fuseAlerts(signatureRecords, mlPredictions) {
  const signatureById = indexById(signatureRecords);
  const mlById = indexById(mlPredictions);
  const idAlignmentSummary = buildIdAlignmentSummary(signatureById, mlById);

  // Stage 2 signature records define the fusion scope: they cover every flow
  // in the Stage 1 sample. Stage 3 predictions are only joined in when their
  // id falls inside that scope; predictions for ids outside it come from a
  // different Stage 3 test set and are not the same flows, so they must not
  // be unioned into the fused alert count.
  const fusedAlerts = [...signatureById.keys()]
    .map((id) => fuseAlert(signatureById.get(id), mlById.get(id) || null))
    .sort((a, b) => {
      if (b.fusionRiskScore !== a.fusionRiskScore) {
        return b.fusionRiskScore - a.fusionRiskScore;
      }
      if (a.requiresAnalystReview !== b.requiresAnalystReview) {
        return a.requiresAnalystReview ? -1 : 1;
      }
      return String(a.id).localeCompare(String(b.id));
    });

  return {
    fusedAlerts,
    outOfScopeMlPredictionIds: idAlignmentSummary.outOfScopeMlPredictionIds,
    idAlignmentSummary,
  };
}

function incrementCounter(counter, key) {
  const safeKey = key || 'Unknown';
  counter[safeKey] = (counter[safeKey] || 0) + 1;
}

function safeDivide(numerator, denominator) {
  return denominator ? Number((numerator / denominator).toFixed(4)) : 0;
}

function calculateF1(precision, recall) {
  return precision + recall === 0 ? 0 : Number(((2 * precision * recall) / (precision + recall)).toFixed(4));
}

function averageScore(alerts) {
  if (!alerts.length) {
    return 0;
  }
  const total = alerts.reduce((sum, alert) => sum + Number(alert.fusionRiskScore || 0), 0);
  return Number((total / alerts.length).toFixed(2));
}

function calculateClassificationMetrics(evaluatedAlerts) {
  const labels = [...new Set(
    evaluatedAlerts.flatMap((record) => [record.trueAttackType, record.predictedAttackType])
  )].sort();

  const confusionMatrix = {};
  const perClass = {};
  let correctCount = 0;

  for (const label of labels) {
    confusionMatrix[label] = {};
    for (const predictedLabel of labels) {
      confusionMatrix[label][predictedLabel] = 0;
    }
  }

  for (const record of evaluatedAlerts) {
    confusionMatrix[record.trueAttackType][record.predictedAttackType] += 1;
    if (record.trueAttackType === record.predictedAttackType) {
      correctCount += 1;
    }
  }

  let macroF1Total = 0;
  let weightedF1Total = 0;

  for (const label of labels) {
    const truePositive = confusionMatrix[label][label] || 0;
    const falseNegative = labels.reduce((sum, predictedLabel) => {
      if (predictedLabel === label) {
        return sum;
      }
      return sum + (confusionMatrix[label][predictedLabel] || 0);
    }, 0);
    const falsePositive = labels.reduce((sum, trueLabel) => {
      if (trueLabel === label) {
        return sum;
      }
      return sum + (confusionMatrix[trueLabel][label] || 0);
    }, 0);
    const support = truePositive + falseNegative;
    const precision = safeDivide(truePositive, truePositive + falsePositive);
    const recall = safeDivide(truePositive, truePositive + falseNegative);
    const f1 = calculateF1(precision, recall);

    perClass[label] = {
      precision,
      recall,
      f1,
      support,
    };

    macroF1Total += f1;
    weightedF1Total += f1 * support;
  }

  return {
    accuracy: safeDivide(correctCount, evaluatedAlerts.length),
    macroF1: labels.length ? Number((macroF1Total / labels.length).toFixed(4)) : 0,
    weightedF1: safeDivide(weightedF1Total, evaluatedAlerts.length),
    perClass,
    confusionMatrix,
  };
}

function calculateBinaryDetectionMetrics(evaluatedAlerts) {
  let truePositive = 0;
  let trueNegative = 0;
  let falsePositive = 0;
  let falseNegative = 0;

  for (const record of evaluatedAlerts) {
    const actualMalicious = record.groundTruthLabel === 'malicious';
    const predictedMalicious = record.predictedAttackType !== 'Benign';

    if (actualMalicious && predictedMalicious) {
      truePositive += 1;
    } else if (!actualMalicious && !predictedMalicious) {
      trueNegative += 1;
    } else if (!actualMalicious && predictedMalicious) {
      falsePositive += 1;
    } else if (actualMalicious && !predictedMalicious) {
      falseNegative += 1;
    }
  }

  const precision = safeDivide(truePositive, truePositive + falsePositive);
  const recall = safeDivide(truePositive, truePositive + falseNegative);
  const f1 = calculateF1(precision, recall);

  return {
    positiveClass: 'malicious',
    negativeClass: 'benign',
    truePositive,
    trueNegative,
    falsePositive,
    falseNegative,
    precision,
    recall,
    specificity: safeDivide(trueNegative, trueNegative + falsePositive),
    f1,
  };
}

function calculateRiskPrioritisationMetrics(evaluatedAlerts) {
  const benignAlerts = evaluatedAlerts.filter((record) => record.groundTruthLabel === 'benign');
  const maliciousAlerts = evaluatedAlerts.filter((record) => record.groundTruthLabel === 'malicious');
  const sortedByRisk = [...evaluatedAlerts].sort((a, b) => b.fusionRiskScore - a.fusionRiskScore);
  const highRiskAlerts = evaluatedAlerts.filter((record) => record.fusionRiskScore >= 70);
  const lowRiskMaliciousAlerts = maliciousAlerts.filter((record) => record.fusionRiskScore < 40);
  const highRiskBenignAlerts = benignAlerts.filter((record) => record.fusionRiskScore >= 70);

  function topPrecision(limit) {
    const topAlerts = sortedByRisk.slice(0, limit);
    const maliciousCount = topAlerts.filter((record) => record.groundTruthLabel === 'malicious').length;
    return safeDivide(maliciousCount, topAlerts.length);
  }

  return {
    averageFusionRiskScoreBenign: averageScore(benignAlerts),
    averageFusionRiskScoreMalicious: averageScore(maliciousAlerts),
    top50Precision: topPrecision(50),
    top100Precision: topPrecision(100),
    top200Precision: topPrecision(200),
    highRiskThreshold: 70,
    highRiskThresholdPrecision: safeDivide(
      highRiskAlerts.filter((record) => record.groundTruthLabel === 'malicious').length,
      highRiskAlerts.length
    ),
    highRiskAlertCount: highRiskAlerts.length,
    benignRecordsWithHighFusionRiskScore: highRiskBenignAlerts.length,
    maliciousRecordsWithLowFusionRiskScore: lowRiskMaliciousAlerts.length,
    lowRiskThresholdForMalicious: 40,
  };
}

function calculateAnalystReviewMetrics(evaluatedAlerts) {
  const reviewAlerts = evaluatedAlerts.filter((record) => record.requiresAnalystReview);
  const reviewedMalicious = reviewAlerts.filter((record) => record.groundTruthLabel === 'malicious').length;
  const reviewedBenign = reviewAlerts.filter((record) => record.groundTruthLabel === 'benign').length;
  const maliciousNotRequiringReview = evaluatedAlerts.filter(
    (record) => record.groundTruthLabel === 'malicious' && !record.requiresAnalystReview
  ).length;
  const benignRequiringReview = reviewedBenign;

  return {
    requiresAnalystReviewCount: reviewAlerts.length,
    reviewRate: safeDivide(reviewAlerts.length, evaluatedAlerts.length),
    reviewedMaliciousCount: reviewedMalicious,
    reviewedBenignCount: reviewedBenign,
    reviewPrecision: safeDivide(reviewedMalicious, reviewAlerts.length),
    maliciousRecordsNotRequiringReview: maliciousNotRequiringReview,
    benignRecordsRequiringReview: benignRequiringReview,
  };
}

function summariseFusionResults(fusedAlerts, groundTruth = null, idAlignmentSummary = null) {
  const safeAlignmentSummary = idAlignmentSummary
    ? {
      stage2RecordCount: idAlignmentSummary.stage2RecordCount,
      stage3PredictionCount: idAlignmentSummary.stage3PredictionCount,
      matchedIdCount: idAlignmentSummary.matchedIdCount,
      stage2OnlyCount: idAlignmentSummary.stage2OnlyCount,
      stage3OutOfScopeCount: idAlignmentSummary.stage3OutOfScopeCount,
      overlapRateAgainstStage2: idAlignmentSummary.overlapRateAgainstStage2,
      overlapRateAgainstStage3: idAlignmentSummary.overlapRateAgainstStage3,
      alignmentStatus: idAlignmentSummary.alignmentStatus,
      alignmentWarning: idAlignmentSummary.alignmentWarning,
      stage2OnlyIdsSample: idAlignmentSummary.stage2OnlyIdsSample || [],
      outOfScopeMlPredictionIdsSample: idAlignmentSummary.outOfScopeMlPredictionIdsSample || [],
    }
    : {
      stage2RecordCount: fusedAlerts.length,
      stage3PredictionCount: 0,
      matchedIdCount: 0,
      stage2OnlyCount: 0,
      stage3OutOfScopeCount: 0,
      overlapRateAgainstStage2: 0,
      overlapRateAgainstStage3: 0,
      alignmentStatus: 'UNKNOWN',
      alignmentWarning: null,
      stage2OnlyIdsSample: [],
      outOfScopeMlPredictionIdsSample: [],
    };

  const summary = {
    totalFusedAlerts: fusedAlerts.length,
    outOfScopeMlPredictionCount: safeAlignmentSummary.stage3OutOfScopeCount,
    idAlignmentSummary: safeAlignmentSummary,
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
    infiltrationMlLimitationCount: 0,
    notes: [
      'Stage 4 is a prototype fusion evaluation, not final IDS performance.',
      'Ground truth is joined only after fusion for evaluation.',
      'Current Stage 3 ML artifacts do not include Infiltration; Stage 4 retains Infiltration signature alerts.',
      'Fusion scope is defined by Stage 2 signature records (the Stage 1 sample). Stage 3 predictions whose id is outside that scope come from a different Stage 3 test set and are excluded from fusion rather than unioned in.',
    ],
  };

  if (safeAlignmentSummary.alignmentWarning) {
    summary.notes.push(safeAlignmentSummary.alignmentWarning);
  }

  if (safeAlignmentSummary.stage3OutOfScopeCount > 0) {
    summary.notes.push(
      `${safeAlignmentSummary.stage3OutOfScopeCount} Stage 3 ML prediction(s) were excluded as out of scope because their id does not match any Stage 2 signature record.`
    );
  }

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
    if (alert.fusionDecision === 'SIGNATURE_ONLY_ML_LIMITATION') {
      summary.infiltrationMlLimitationCount += 1;
    }
  }

  if (groundTruth) {
    const evaluatedAlerts = [];

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
      evaluatedAlerts.push({
        id: alert.id,
        trueAttackType,
        predictedAttackType: alert.fusionAttackType || 'Unknown',
        groundTruthLabel,
        fusionRiskScore: alert.fusionRiskScore,
        requiresAnalystReview: alert.requiresAnalystReview,
      });
      summary.groundTruthEvaluation.evaluatedAlertCount += 1;
      incrementCounter(summary.groundTruthEvaluation.countByTrueAttackType, trueAttackType);
      if (alert.fusionAttackType === trueAttackType) {
        summary.groundTruthEvaluation.matchingFusionAttackTypeCount += 1;
      }
    }

    const evaluated = summary.groundTruthEvaluation.evaluatedAlertCount;
    summary.groundTruthEvaluation.simpleFusionAccuracy = evaluated
      ? Number((summary.groundTruthEvaluation.matchingFusionAttackTypeCount / evaluated).toFixed(4))
      : 0;

    summary.groundTruthEvaluation.classificationMetrics = calculateClassificationMetrics(evaluatedAlerts);
    summary.groundTruthEvaluation.binaryDetectionMetrics = calculateBinaryDetectionMetrics(evaluatedAlerts);
    summary.groundTruthEvaluation.falsePositiveStyleCount =
      summary.groundTruthEvaluation.binaryDetectionMetrics.falsePositive;
    summary.groundTruthEvaluation.falseNegativeStyleCount =
      summary.groundTruthEvaluation.binaryDetectionMetrics.falseNegative;
    summary.groundTruthEvaluation.riskPrioritisationMetrics = calculateRiskPrioritisationMetrics(evaluatedAlerts);
    summary.groundTruthEvaluation.analystReviewMetrics = calculateAnalystReviewMetrics(evaluatedAlerts);
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
