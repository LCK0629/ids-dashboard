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
  const { fusedAlerts, outOfScopeMlPredictionIds } = fuseAlerts(signatureOutput, mlPredictions);
  const groundTruth = loadJsonFile(groundTruthPath, null);
  const evaluationSummary = summariseFusionResults(fusedAlerts, groundTruth, outOfScopeMlPredictionIds);

  fs.mkdirSync(outputDir, { recursive: true });
  fs.mkdirSync(evaluationDir, { recursive: true });
  fs.writeFileSync(fusionOutputPath, `${JSON.stringify(fusedAlerts, null, 2)}\n`, 'utf8');
  fs.writeFileSync(evaluationJsonPath, `${JSON.stringify(evaluationSummary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(evaluationMarkdownPath, renderEvaluationMarkdown(evaluationSummary), 'utf8');

  console.log(`Signature records loaded: ${signatureOutput.length}`);
  console.log(`ML predictions loaded: ${mlPredictions.length}`);
  console.log(`Fused alerts written: ${fusedAlerts.length}`);
  console.log(`Stage 3 predictions excluded as out of scope: ${outOfScopeMlPredictionIds.length}`);
  console.log(`Requires analyst review: ${evaluationSummary.countRequiringAnalystReview}`);
  console.log(`Fusion output: ${fusionOutputPath}`);
  console.log(`Evaluation summary: ${evaluationMarkdownPath}`);
}

main();
