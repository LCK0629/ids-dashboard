const fs = require('fs');
const path = require('path');

const {
  loadJsonFile,
  loadCsvFile,
  applySignatures,
  summariseSignatureResults,
} = require('../core/signature-engine');

const repoRoot = path.resolve(__dirname, '..', '..');
const featureInputPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'flow-feature-sample.csv');
const groundTruthPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'ground-truth.json');
const rulesPath = path.join(repoRoot, 'stage-2', 'rules', 'flow-signatures.json');
const outputPath = path.join(repoRoot, 'stage-2', 'data', 'signature-output.sample.json');
const evaluationDir = path.join(repoRoot, 'stage-2', 'evaluation');
const evaluationJsonPath = path.join(evaluationDir, 'signature-evaluation-summary.json');
const evaluationMarkdownPath = path.join(evaluationDir, 'signature-evaluation-summary.md');

function printObject(title, value) {
  console.log(title);
  const entries = Object.entries(value);
  if (entries.length === 0) {
    console.log('  none');
    return;
  }

  for (const [key, count] of entries) {
    console.log(`  ${key}: ${count}`);
  }
}

function safeDivide(numerator, denominator) {
  return denominator === 0 ? 0 : numerator / denominator;
}

function buildEvaluationSummary(signedAlerts) {
  const totalRecords = signedAlerts.length;
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  const hitsBySignature = {};
  const hitsByPredictedAttackType = {};
  const coverageByTrueAttackType = {};

  for (const alert of signedAlerts) {
    const isHit = alert.signatureHit === true;
    const isMalicious = alert.groundTruth === 'malicious';
    const trueAttackType = alert.trueAttackType || 'Unknown';

    if (!coverageByTrueAttackType[trueAttackType]) {
      coverageByTrueAttackType[trueAttackType] = {
        total: 0,
        signatureHits: 0,
        coverage: 0,
      };
    }
    coverageByTrueAttackType[trueAttackType].total += 1;

    if (isHit) {
      hitsBySignature[alert.signatureId] = (hitsBySignature[alert.signatureId] || 0) + 1;
      hitsByPredictedAttackType[alert.signatureAttackType] =
        (hitsByPredictedAttackType[alert.signatureAttackType] || 0) + 1;
      coverageByTrueAttackType[trueAttackType].signatureHits += 1;
    }

    if (isHit && isMalicious) {
      truePositives += 1;
    } else if (isHit && !isMalicious) {
      falsePositives += 1;
    } else if (!isHit && isMalicious) {
      falseNegatives += 1;
    } else {
      trueNegatives += 1;
    }
  }

  for (const value of Object.values(coverageByTrueAttackType)) {
    value.coverage = safeDivide(value.signatureHits, value.total);
  }

  const signatureHits = truePositives + falsePositives;
  const noSignatureHits = falseNegatives + trueNegatives;
  const precision = safeDivide(truePositives, truePositives + falsePositives);
  const recall = safeDivide(truePositives, truePositives + falseNegatives);
  const f1Score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return {
    totalRecords,
    signatureHits,
    noSignatureHits,
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    precision,
    recall,
    f1Score,
    benignRecordsWithSignatureHit: falsePositives,
    hitsBySignature,
    hitsByPredictedAttackType,
    coverageByTrueAttackType,
    notes: [
      'Prediction uses flow-feature-sample.csv only.',
      'ground-truth.json is joined only after prediction for evaluation.',
      'Rules are prototype flow-level heuristics, not full packet-payload Snort rules.',
    ],
  };
}

function formatPercent(value) {
  return `${(value * 100).toFixed(2)}%`;
}

function renderEvaluationMarkdown(summary) {
  const lines = [
    '# Stage 2 Signature Evaluation Summary',
    '',
    '## Overall Metrics',
    '',
    `- Total records: ${summary.totalRecords}`,
    `- Signature hits: ${summary.signatureHits}`,
    `- No signature hits: ${summary.noSignatureHits}`,
    `- True positives: ${summary.truePositives}`,
    `- False positives: ${summary.falsePositives}`,
    `- False negatives: ${summary.falseNegatives}`,
    `- True negatives: ${summary.trueNegatives}`,
    `- Precision: ${summary.precision.toFixed(4)} (${formatPercent(summary.precision)})`,
    `- Recall: ${summary.recall.toFixed(4)} (${formatPercent(summary.recall)})`,
    `- F1 score: ${summary.f1Score.toFixed(4)} (${formatPercent(summary.f1Score)})`,
    `- Benign records with signature hit: ${summary.benignRecordsWithSignatureHit}`,
    '',
    '## Hits By Signature',
    '',
  ];

  for (const [signatureId, count] of Object.entries(summary.hitsBySignature)) {
    lines.push(`- ${signatureId}: ${count}`);
  }

  lines.push('', '## Hits By Predicted Attack Type', '');
  for (const [attackType, count] of Object.entries(summary.hitsByPredictedAttackType)) {
    lines.push(`- ${attackType}: ${count}`);
  }

  lines.push('', '## Coverage By True Attack Type', '');
  for (const [attackType, value] of Object.entries(summary.coverageByTrueAttackType)) {
    lines.push(`- ${attackType}: ${value.signatureHits}/${value.total} (${formatPercent(value.coverage)})`);
  }

  lines.push('', '## Notes', '');
  for (const note of summary.notes) {
    lines.push(`- ${note}`);
  }

  return `${lines.join('\n')}\n`;
}

function main() {
  const flowFeatures = loadCsvFile(featureInputPath);
  const signatureRules = loadJsonFile(rulesPath);
  const signedFlows = applySignatures(flowFeatures, signatureRules);
  const groundTruth = loadJsonFile(groundTruthPath);

  const signedAlerts = signedFlows.map((flow) => {
    const truth = groundTruth[flow.id] || {};
    return {
      ...flow,
      rawLabel: truth.rawLabel || null,
      trueAttackType: truth.mappedAttackType || null,
      groundTruth: truth.groundTruth || null,
    };
  });

  fs.writeFileSync(outputPath, `${JSON.stringify(signedAlerts, null, 2)}\n`, 'utf8');
  const summary = summariseSignatureResults(signedAlerts);
  const evaluationSummary = buildEvaluationSummary(signedAlerts);

  fs.mkdirSync(evaluationDir, { recursive: true });
  fs.writeFileSync(evaluationJsonPath, `${JSON.stringify(evaluationSummary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(evaluationMarkdownPath, renderEvaluationMarkdown(evaluationSummary), 'utf8');

  console.log(`Total alerts: ${summary.totalAlerts}`);
  console.log(`Signature hits: ${summary.signatureHits}`);
  console.log(`No signature hits: ${summary.noSignatureHits}`);
  console.log(`Signature hit rate: ${(summary.signatureHitRate * 100).toFixed(2)}%`);
  printObject('Hits by signature:', summary.hitsBySignature);
  printObject('Hits by true attack type:', summary.hitsByAttackType);
  console.log(`Benign alerts with signature hit: ${summary.benignAlertsWithSignatureHit}`);
  console.log(`Evaluation summary JSON: ${evaluationJsonPath}`);
  console.log(`Evaluation summary Markdown: ${evaluationMarkdownPath}`);

  if (summary.benignAlertsWithSignatureHit !== 0) {
    throw new Error('Benign alerts must not trigger flow-based signatures.');
  }
}

main();
