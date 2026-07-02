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

  console.log(`Total alerts: ${summary.totalAlerts}`);
  console.log(`Signature hits: ${summary.signatureHits}`);
  console.log(`No signature hits: ${summary.noSignatureHits}`);
  console.log(`Signature hit rate: ${(summary.signatureHitRate * 100).toFixed(2)}%`);
  printObject('Hits by signature:', summary.hitsBySignature);
  printObject('Hits by true attack type:', summary.hitsByAttackType);
  console.log(`Benign alerts with signature hit: ${summary.benignAlertsWithSignatureHit}`);

  if (summary.benignAlertsWithSignatureHit !== 0) {
    throw new Error('Benign alerts must not trigger flow-based signatures.');
  }
}

main();
