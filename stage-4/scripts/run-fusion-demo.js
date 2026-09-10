const fs = require('fs');
const path = require('path');

const {
  loadJsonFile,
  fuseAlerts,
  fuseAlertsLegacyBaseline,
  summariseFusionResults,
} = require('../core/fusion-engine');

const repoRoot = path.resolve(__dirname, '..', '..');
const signatureOutputPath = path.join(repoRoot, 'stage-2', 'data', 'signature-output.sample.json');
const mlPredictionsPath = path.join(repoRoot, 'stage-3', 'outputs', 'ml-predictions.sample.json');
const groundTruthPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'ground-truth.json');
const defaultOutputDir = path.join(repoRoot, 'stage-4', 'outputs');
const defaultEvaluationDir = path.join(repoRoot, 'stage-4', 'evaluation');

function buildOutputPaths(outputDir, evaluationDir) {
  return {
    outputDir,
    evaluationDir,
    fusionOutputPath: path.join(outputDir, 'fusion-alerts.sample.json'),
    evaluationJsonPath: path.join(evaluationDir, 'fusion-evaluation-summary.json'),
    evaluationMarkdownPath: path.join(evaluationDir, 'fusion-evaluation-summary.md'),
    mlEvidenceIntegrationSummaryPath: path.join(evaluationDir, 'ml-evidence-integration-summary.json'),
  };
}

function parseArgs(argv) {
  const args = {
    mlPredictionsPath,
    outputDir: defaultOutputDir,
    evaluationDir: defaultEvaluationDir,
  };

  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--ml-predictions') {
      if (!argv[index + 1]) {
        throw new Error('--ml-predictions requires a file path');
      }
      args.mlPredictionsPath = path.resolve(argv[index + 1]);
      index += 1;
    } else if (argument === '--output-dir') {
      if (!argv[index + 1]) {
        throw new Error('--output-dir requires a directory path');
      }
      args.outputDir = path.resolve(argv[index + 1]);
      index += 1;
    } else if (argument === '--evaluation-dir') {
      if (!argv[index + 1]) {
        throw new Error('--evaluation-dir requires a directory path');
      }
      args.evaluationDir = path.resolve(argv[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  return args;
}

function repoRelativePath(filePath) {
  const relativePath = path.relative(repoRoot, filePath);
  if (!relativePath.startsWith('..') && !path.isAbsolute(relativePath)) {
    return relativePath.split(path.sep).join('/');
  }
  return filePath.split(path.sep).join('/');
}

function renderCounter(counter) {
  const entries = Object.entries(counter || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return '- none';
  }
  return entries.map(([key, value]) => `- ${key}: ${value}`).join('\n');
}

function renderPerClassMetrics(perClass) {
  const entries = Object.entries(perClass || {}).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) {
    return '- none';
  }
  return entries
    .map(([label, metrics]) => (
      `- ${label}: precision ${metrics.precision}, recall ${metrics.recall}, F1 ${metrics.f1}, support ${metrics.support}`
    ))
    .join('\n');
}

function renderConfusionMatrix(confusionMatrix) {
  const labels = Object.keys(confusionMatrix || {}).sort();
  if (labels.length === 0) {
    return '- none';
  }

  const lines = [
    `| True \\ Predicted | ${labels.join(' | ')} |`,
    `|---|${labels.map(() => '---').join('|')}|`,
  ];

  for (const trueLabel of labels) {
    const row = labels.map((predictedLabel) => confusionMatrix[trueLabel][predictedLabel] || 0);
    lines.push(`| ${trueLabel} | ${row.join(' | ')} |`);
  }

  return lines.join('\n');
}

function renderPercent(rate) {
  return `${(Number(rate || 0) * 100).toFixed(2)}%`;
}

function renderIdSample(ids) {
  if (!ids || ids.length === 0) {
    return '- none';
  }
  return ids.map((id) => `- ${id}`).join('\n');
}

function renderEvaluationMarkdown(summary) {
  const lines = [
    '# Stage 4 Fusion Evaluation Summary',
    '',
    'Stage 4 combines Stage 2 signature evidence and Stage 3 ML predictions. Ground truth is joined only after fusion for this summary.',
    '',
    `- Total fused alerts: ${summary.totalFusedAlerts}`,
    `- Stage 3 predictions excluded as out of scope: ${summary.outOfScopeMlPredictionCount}`,
    `- Requires analyst review: ${summary.countRequiringAnalystReview}`,
    `- Average fusion risk score: ${summary.averageFusionRiskScore}`,
    `- Max fusion risk score: ${summary.maxFusionRiskScore}`,
    `- Min fusion risk score: ${summary.minFusionRiskScore}`,
    `- Signature / ML agreement count: ${summary.signatureMlAgreementCount}`,
    `- Signature / ML disagreement count: ${summary.signatureMlDisagreementCount}`,
    `- ML-only alert count: ${summary.mlOnlyAlertCount}`,
    `- Signature-only alert count: ${summary.signatureOnlyAlertCount}`,
    `- Infiltration ML limitation count: ${summary.infiltrationMlLimitationCount}`,
    '',
    '## ID Alignment Summary',
    '',
    'Fusion is Stage-2-scoped. ML predictions are used only when IDs match Stage 2 records. Out-of-scope ML predictions are reported for debugging but are not inserted into the dashboard fusion queue.',
    '',
    `- Stage 2 record count: ${summary.idAlignmentSummary.stage2RecordCount}`,
    `- Stage 3 record count: ${summary.idAlignmentSummary.stage3RecordCount}`,
    `- Stage 3 available prediction count: ${summary.idAlignmentSummary.stage3AvailablePredictionCount}`,
    `- Stage 3 unavailable prediction count: ${summary.idAlignmentSummary.stage3UnavailablePredictionCount}`,
    `- Matched ID count: ${summary.idAlignmentSummary.matchedIdCount}`,
    `- Matched available prediction count: ${summary.idAlignmentSummary.matchedAvailablePredictionCount}`,
    `- Matched unavailable prediction count: ${summary.idAlignmentSummary.matchedUnavailablePredictionCount}`,
    `- Stage 2 only count: ${summary.idAlignmentSummary.stage2OnlyCount}`,
    `- Stage 3 out-of-scope count: ${summary.idAlignmentSummary.stage3OutOfScopeCount}`,
    `- Overlap rate against Stage 2: ${renderPercent(summary.idAlignmentSummary.overlapRateAgainstStage2)}`,
    `- Overlap rate against Stage 3: ${renderPercent(summary.idAlignmentSummary.overlapRateAgainstStage3)}`,
    `- Alignment status: ${summary.idAlignmentSummary.alignmentStatus}`,
    `- Alignment warning: ${summary.idAlignmentSummary.alignmentWarning || 'none'}`,
    '',
    '### Stage 2-Only ID Sample',
    '',
    renderIdSample(summary.idAlignmentSummary.stage2OnlyIdsSample),
    '',
    '### Out-of-Scope Stage 3 ID Sample',
    '',
    renderIdSample(summary.idAlignmentSummary.outOfScopeMlPredictionIdsSample),
    '',
    '## Count By Fusion Decision',
    '',
    renderCounter(summary.countByFusionDecision),
    '',
    '## Count By Fusion Confidence Level',
    '',
    renderCounter(summary.countByFusionConfidenceLevel),
    '',
    '## Count By Fusion Attack Type',
    '',
    renderCounter(summary.countByFusionAttackType),
    '',
    '## Notes',
    '',
    ...summary.notes.map((note) => `- ${note}`),
  ];

  if (summary.groundTruthEvaluation) {
    lines.push(
      '',
      '## Ground Truth Evaluation',
      '',
      `- Evaluated alert count: ${summary.groundTruthEvaluation.evaluatedAlertCount}`,
      `- Matching fusion attack type count: ${summary.groundTruthEvaluation.matchingFusionAttackTypeCount}`,
      `- Simple fusion accuracy: ${summary.groundTruthEvaluation.simpleFusionAccuracy}`,
      `- False positive style count: ${summary.groundTruthEvaluation.falsePositiveStyleCount}`,
      `- False negative style count: ${summary.groundTruthEvaluation.falseNegativeStyleCount}`,
      '',
      '## Classification Metrics',
      '',
      `- Accuracy: ${summary.groundTruthEvaluation.classificationMetrics.accuracy}`,
      `- Macro F1: ${summary.groundTruthEvaluation.classificationMetrics.macroF1}`,
      `- Weighted F1: ${summary.groundTruthEvaluation.classificationMetrics.weightedF1}`,
      '',
      '### Binary Detection Metrics',
      '',
      `- Positive class: ${summary.groundTruthEvaluation.binaryDetectionMetrics.positiveClass}`,
      `- Negative class: ${summary.groundTruthEvaluation.binaryDetectionMetrics.negativeClass}`,
      `- True positive: ${summary.groundTruthEvaluation.binaryDetectionMetrics.truePositive}`,
      `- True negative: ${summary.groundTruthEvaluation.binaryDetectionMetrics.trueNegative}`,
      `- False positive: ${summary.groundTruthEvaluation.binaryDetectionMetrics.falsePositive}`,
      `- False negative: ${summary.groundTruthEvaluation.binaryDetectionMetrics.falseNegative}`,
      `- Binary precision: ${summary.groundTruthEvaluation.binaryDetectionMetrics.precision}`,
      `- Binary recall: ${summary.groundTruthEvaluation.binaryDetectionMetrics.recall}`,
      `- Binary specificity: ${summary.groundTruthEvaluation.binaryDetectionMetrics.specificity}`,
      `- Binary F1: ${summary.groundTruthEvaluation.binaryDetectionMetrics.f1}`,
      '',
      '### Per-Class Precision / Recall / F1',
      '',
      renderPerClassMetrics(summary.groundTruthEvaluation.classificationMetrics.perClass),
      '',
      '### Confusion Matrix',
      '',
      renderConfusionMatrix(summary.groundTruthEvaluation.classificationMetrics.confusionMatrix),
      '',
      '## Risk Prioritisation Metrics',
      '',
      `- Average fusion risk score for benign records: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.averageFusionRiskScoreBenign}`,
      `- Average fusion risk score for malicious records: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.averageFusionRiskScoreMalicious}`,
      `- Top-50 precision: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.top50Precision}`,
      `- Top-100 precision: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.top100Precision}`,
      `- Top-200 precision: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.top200Precision}`,
      `- High-risk threshold precision, fusionRiskScore >= ${summary.groundTruthEvaluation.riskPrioritisationMetrics.highRiskThreshold}: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.highRiskThresholdPrecision}`,
      `- High-risk alert count: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.highRiskAlertCount}`,
      `- Benign records with high fusionRiskScore: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.benignRecordsWithHighFusionRiskScore}`,
      `- Malicious records with low fusionRiskScore, fusionRiskScore < ${summary.groundTruthEvaluation.riskPrioritisationMetrics.lowRiskThresholdForMalicious}: ${summary.groundTruthEvaluation.riskPrioritisationMetrics.maliciousRecordsWithLowFusionRiskScore}`,
      '',
      '## Analyst Review Metrics',
      '',
      `- Requires analyst review count: ${summary.groundTruthEvaluation.analystReviewMetrics.requiresAnalystReviewCount}`,
      `- Review rate: ${summary.groundTruthEvaluation.analystReviewMetrics.reviewRate}`,
      `- Reviewed malicious count: ${summary.groundTruthEvaluation.analystReviewMetrics.reviewedMaliciousCount}`,
      `- Reviewed benign count: ${summary.groundTruthEvaluation.analystReviewMetrics.reviewedBenignCount}`,
      `- Review precision: ${summary.groundTruthEvaluation.analystReviewMetrics.reviewPrecision}`,
      `- Malicious records not requiring review: ${summary.groundTruthEvaluation.analystReviewMetrics.maliciousRecordsNotRequiringReview}`,
      `- Benign records requiring review: ${summary.groundTruthEvaluation.analystReviewMetrics.benignRecordsRequiringReview}`,
      '',
      '### Count By True Attack Type',
      '',
      renderCounter(summary.groundTruthEvaluation.countByTrueAttackType),
      '',
      'This is a prototype Stage 4 evaluation. It should not be reported as final production IDS accuracy.'
    );
  }

  return `${lines.join('\n')}\n`;
}

function categorizeScoreChange(beforeAlert, afterAlert) {
  if (afterAlert.mlRecordPresent && !afterAlert.mlEvidenceAvailable) {
    return 'unavailable_ml_prediction_not_valid_evidence';
  }
  if (
    afterAlert.mlEvidenceAvailable
    && afterAlert.mlPredictedAttackType === 'Benign'
    && Number(beforeAlert.baseRiskScore || 0) > Number(afterAlert.mlThreatEvidenceScore || 0)
  ) {
    return 'benign_confidence_no_longer_treated_as_threat_risk';
  }
  return 'other_requires_investigation';
}

function compareFusionScores(beforeAlerts, afterAlerts) {
  const beforeById = new Map(beforeAlerts.map((alert) => [String(alert.id), alert]));
  const changedRecords = [];
  const categories = {};
  let unchangedFusionRiskScoreCount = 0;
  let changedFusionRiskScoreCount = 0;
  let changedFusionDecisionCount = 0;

  for (const afterAlert of afterAlerts) {
    const beforeAlert = beforeById.get(String(afterAlert.id));
    if (!beforeAlert) {
      continue;
    }
    const scoreChanged = beforeAlert.fusionRiskScore !== afterAlert.fusionRiskScore;
    const decisionChanged = beforeAlert.fusionDecision !== afterAlert.fusionDecision;

    if (!scoreChanged) {
      unchangedFusionRiskScoreCount += 1;
    } else {
      changedFusionRiskScoreCount += 1;
    }

    if (decisionChanged) {
      changedFusionDecisionCount += 1;
    }

    if (!scoreChanged && !decisionChanged) {
      continue;
    }

    const reason = categorizeScoreChange(beforeAlert, afterAlert);
    categories[reason] = (categories[reason] || 0) + 1;
    changedRecords.push({
      id: afterAlert.id,
      beforeFusionRiskScore: beforeAlert.fusionRiskScore,
      afterFusionRiskScore: afterAlert.fusionRiskScore,
      beforeFusionDecision: beforeAlert.fusionDecision,
      afterFusionDecision: afterAlert.fusionDecision,
      reason,
    });
  }

  return {
    unchangedFusionRiskScoreCount,
    changedFusionRiskScoreCount,
    changedFusionDecisionCount,
    changedFusionRiskScoreOrDecisionCount: changedRecords.length,
    categorizedIntentionalChanges: categories,
    changedRecords,
  };
}

function countMlExplanations(fusedAlerts) {
  const counts = {
    available: 0,
    unavailable: 0,
    unavailableReasons: {
      predictionUnavailable: 0,
      treeShapGenerationFailure: 0,
      additivityFailure: 0,
      other: 0,
    },
  };

  for (const alert of fusedAlerts) {
    if (!alert.mlExplanation) {
      continue;
    }
    if (alert.mlExplanation.status === 'available') {
      counts.available += 1;
    } else {
      counts.unavailable += 1;
      const reason = alert.mlExplanation.reason || 'unknown';
      if (reason === 'prediction_unavailable') {
        counts.unavailableReasons.predictionUnavailable += 1;
      } else if (String(reason).startsWith('treeshap_generation_failed')) {
        counts.unavailableReasons.treeShapGenerationFailure += 1;
      } else if (reason === 'additivity_check_failed') {
        counts.unavailableReasons.additivityFailure += 1;
      } else {
        counts.unavailableReasons.other += 1;
      }
    }
  }

  return counts;
}

function buildMlEvidenceIntegrationSummary({
  signatureOutput,
  mlPredictions,
  fusedAlerts,
  legacyBaselineAlerts,
  idAlignmentSummary,
  selectedMlPredictionsPath,
  fusionOutputPath,
}) {
  const explanationCounts = countMlExplanations(fusedAlerts);
  const scoreRegression = compareFusionScores(legacyBaselineAlerts, fusedAlerts);
  const firstModelProvenance = mlPredictions.find((record) => record && record.modelProvenance)?.modelProvenance || {};

  return {
    runMode: selectedMlPredictionsPath === mlPredictionsPath ? 'default_legacy_sample' : 'explicit_ml_prediction_file',
    sourceArtifactSemantics: selectedMlPredictionsPath === mlPredictionsPath
      ? 'committed legacy Stage 3 sample without predictionStatus'
      : 'explicit Stage 3 prediction artifact supplied by --ml-predictions',
    signatureInputPath: repoRelativePath(signatureOutputPath),
    mlPredictionInputPath: repoRelativePath(selectedMlPredictionsPath),
    fusionOutputPath: repoRelativePath(fusionOutputPath),
    inputStage2RecordCount: signatureOutput.length,
    stage3RecordCount: idAlignmentSummary.stage3RecordCount,
    stage3AvailablePredictionCount: idAlignmentSummary.stage3AvailablePredictionCount,
    stage3UnavailablePredictionCount: idAlignmentSummary.stage3UnavailablePredictionCount,
    matchedRecordCount: idAlignmentSummary.matchedStage3RecordCount,
    matchedValidMlPredictionCount: idAlignmentSummary.matchedAvailablePredictionCount,
    matchedUnavailablePredictionCount: idAlignmentSummary.matchedUnavailablePredictionCount,
    explanationAvailableCountPropagated: explanationCounts.available,
    explanationUnavailableCountPropagated: explanationCounts.unavailable,
    explanationUnavailableReasonsPropagated: explanationCounts.unavailableReasons,
    fusionScoreChangedCount: scoreRegression.changedFusionRiskScoreCount,
    fusionScoreUnchangedCount: scoreRegression.unchangedFusionRiskScoreCount,
    fusionDecisionChangedCount: scoreRegression.changedFusionDecisionCount,
    fusionScoreOrDecisionChangedCount: scoreRegression.changedFusionRiskScoreOrDecisionCount,
    categorizedIntentionalChanges: scoreRegression.categorizedIntentionalChanges,
    changedRecords: scoreRegression.changedRecords,
    infiltrationLimitationCount: fusedAlerts.filter((alert) => alert.fusionDecision === 'SIGNATURE_ONLY_ML_LIMITATION').length,
    modelSha256: firstModelProvenance.modelSha256 || null,
    notes: [
      'Ground truth is not loaded until after fusion output is produced.',
      'modelConfidence is classifier confidence, not threat risk.',
      'mlThreatEvidenceScore is the Stage 4 class-aware threat evidence derived from modelConfidence.',
      'TreeSHAP evidence is passed through only and is not used in fusion scoring.',
    ],
  };
}

function main() {
  const args = parseArgs(process.argv);
  const paths = buildOutputPaths(args.outputDir, args.evaluationDir);
  const signatureOutput = loadJsonFile(signatureOutputPath);
  const mlPredictions = loadJsonFile(args.mlPredictionsPath);
  const { fusedAlerts, outOfScopeMlPredictionIds, idAlignmentSummary } = fuseAlerts(signatureOutput, mlPredictions);
  const legacyBaseline = fuseAlertsLegacyBaseline(signatureOutput, mlPredictions);
  const groundTruth = loadJsonFile(groundTruthPath, null);
  const evaluationSummary = summariseFusionResults(fusedAlerts, groundTruth, idAlignmentSummary);
  const mlEvidenceIntegrationSummary = buildMlEvidenceIntegrationSummary({
    signatureOutput,
    mlPredictions,
    fusedAlerts,
    legacyBaselineAlerts: legacyBaseline.fusedAlerts,
    idAlignmentSummary,
    selectedMlPredictionsPath: args.mlPredictionsPath,
    fusionOutputPath: paths.fusionOutputPath,
  });

  fs.mkdirSync(paths.outputDir, { recursive: true });
  fs.mkdirSync(paths.evaluationDir, { recursive: true });
  fs.writeFileSync(paths.fusionOutputPath, `${JSON.stringify(fusedAlerts, null, 2)}\n`, 'utf8');
  fs.writeFileSync(paths.evaluationJsonPath, `${JSON.stringify(evaluationSummary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(paths.evaluationMarkdownPath, renderEvaluationMarkdown(evaluationSummary), 'utf8');
  fs.writeFileSync(
    paths.mlEvidenceIntegrationSummaryPath,
    `${JSON.stringify(mlEvidenceIntegrationSummary, null, 2)}\n`,
    'utf8'
  );

  console.log(`Signature records loaded: ${signatureOutput.length}`);
  console.log(`ML predictions loaded: ${mlPredictions.length}`);
  console.log(`Fused alerts written: ${fusedAlerts.length}`);
  console.log(`Stage 3 predictions excluded as out of scope: ${outOfScopeMlPredictionIds.length}`);
  console.log(`Stage 2 records: ${idAlignmentSummary.stage2RecordCount}`);
  console.log(`Stage 3 predictions: ${idAlignmentSummary.stage3PredictionCount}`);
  console.log(`Matched IDs: ${idAlignmentSummary.matchedIdCount}`);
  console.log(`Stage 2 only IDs: ${idAlignmentSummary.stage2OnlyCount}`);
  console.log(`Stage 3 out-of-scope IDs: ${idAlignmentSummary.stage3OutOfScopeCount}`);
  console.log(`Overlap rate against Stage 2: ${renderPercent(idAlignmentSummary.overlapRateAgainstStage2)}`);
  console.log(`Overlap rate against Stage 3: ${renderPercent(idAlignmentSummary.overlapRateAgainstStage3)}`);
  console.log(`Alignment status: ${idAlignmentSummary.alignmentStatus}`);
  if (idAlignmentSummary.alignmentWarning) {
    console.log(`Alignment warning: ${idAlignmentSummary.alignmentWarning}`);
  }
  console.log(`Requires analyst review: ${evaluationSummary.countRequiringAnalystReview}`);
  console.log(`ML evidence available: ${idAlignmentSummary.stage3AvailablePredictionCount}`);
  console.log(`ML evidence unavailable: ${idAlignmentSummary.stage3UnavailablePredictionCount}`);
  console.log(`TreeSHAP explanations propagated: ${mlEvidenceIntegrationSummary.explanationAvailableCountPropagated}`);
  console.log(`Fusion score/decision changes vs legacy confidence-risk semantics: ${mlEvidenceIntegrationSummary.fusionScoreOrDecisionChangedCount}`);
  console.log(`Fusion output: ${paths.fusionOutputPath}`);
  console.log(`Evaluation summary: ${paths.evaluationMarkdownPath}`);
  console.log(`ML evidence integration summary: ${paths.mlEvidenceIntegrationSummaryPath}`);
}

main();
