const fs = require('fs');
const path = require('path');

const {
  loadJsonFile,
  fuseAlerts,
  summariseFusionResults,
} = require('../core/fusion-engine');

const repoRoot = path.resolve(__dirname, '..', '..');
const signatureOutputPath = path.join(repoRoot, 'stage-2', 'data', 'signature-output.sample.json');
const mlPredictionsPath = path.join(repoRoot, 'stage-3', 'outputs', 'ml-predictions.sample.json');
const groundTruthPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'ground-truth.json');
const outputDir = path.join(repoRoot, 'stage-4', 'outputs');
const evaluationDir = path.join(repoRoot, 'stage-4', 'evaluation');
const fusionOutputPath = path.join(outputDir, 'fusion-alerts.sample.json');
const evaluationJsonPath = path.join(evaluationDir, 'fusion-evaluation-summary.json');
const evaluationMarkdownPath = path.join(evaluationDir, 'fusion-evaluation-summary.md');

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
    `- Stage 3 prediction count: ${summary.idAlignmentSummary.stage3PredictionCount}`,
    `- Matched ID count: ${summary.idAlignmentSummary.matchedIdCount}`,
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

function main() {
  const signatureOutput = loadJsonFile(signatureOutputPath);
  const mlPredictions = loadJsonFile(mlPredictionsPath);
  const { fusedAlerts, outOfScopeMlPredictionIds, idAlignmentSummary } = fuseAlerts(signatureOutput, mlPredictions);
  const groundTruth = loadJsonFile(groundTruthPath, null);
  const evaluationSummary = summariseFusionResults(fusedAlerts, groundTruth, idAlignmentSummary);

  fs.mkdirSync(outputDir, { recursive: true });
  fs.mkdirSync(evaluationDir, { recursive: true });
  fs.writeFileSync(fusionOutputPath, `${JSON.stringify(fusedAlerts, null, 2)}\n`, 'utf8');
  fs.writeFileSync(evaluationJsonPath, `${JSON.stringify(evaluationSummary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(evaluationMarkdownPath, renderEvaluationMarkdown(evaluationSummary), 'utf8');

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
  console.log(`Fusion output: ${fusionOutputPath}`);
  console.log(`Evaluation summary: ${evaluationMarkdownPath}`);
}

main();
