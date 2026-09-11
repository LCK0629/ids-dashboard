import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  ANALYST_SCHEMA_VERSION,
  DEMO_ARTIFACT_TYPE,
  findForbiddenGroundTruthPaths,
  validateDemoArtifact,
} from '../src/data-contract/analystDashboardContract.js';
import { buildAnalystAlert, findPrivacyViolations } from './export-dashboard-data.mjs';

const require = createRequire(import.meta.url);
const { fuseAlert } = require('../../stage-4/core/fusion-engine.js');
const { adjustAlertsWithFeedback } = require('../../stage-5/core/feedback-engine.js');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..', '..');
const defaultConfigPath = path.join(repoRoot, 'stage-5', 'config', 'adaptation-config.json');
const defaultOutputPath = path.join(repoRoot, 'dashboard', 'src', 'data', 'adaptation-demo-scenarios.v1.json');

function signatureInput(id, overrides = {}) {
  return {
    id,
    protocol: 'TCP',
    destinationPort: 443,
    flowDuration: 1200,
    totalFwdPackets: 24,
    totalBwdPackets: 8,
    flowPacketsPerSecond: 26.7,
    flowBytesPerSecond: 4800,
    packetLengthMean: 180,
    synFlagCount: 2,
    ackFlagCount: 8,
    signatureHit: false,
    signatureId: null,
    signatureAttackType: null,
    signatureSeverity: null,
    signaturePlainExplanation: null,
    matchedConditionsReadable: [],
    signatureTechnicalDetails: null,
    ...overrides,
  };
}

function mlInput(id, overrides = {}) {
  return {
    id,
    predictionStatus: 'available',
    predictedClassIndex: 4,
    predictedAttackType: 'DoS',
    modelConfidence: 0.9,
    classProbabilities: { Benign: 0.1, DoS: 0.9 },
    secondBestClass: 'Benign',
    predictionMargin: 0.8,
    modelProvenance: null,
    mlExplanation: {
      status: 'unavailable',
      reason: 'demonstration_scenario_no_model_run',
      method: null,
    },
    ...overrides,
  };
}

function fusedDetectorRecord(id, detectorOverrides = {}) {
  return fuseAlert(
    signatureInput(id, detectorOverrides.signature),
    mlInput(id, detectorOverrides.ml)
  );
}

function historicalFixture(prefix, count, feedbackTypes, detectorOverrides = {}) {
  const alerts = [];
  const feedback = [];
  for (let index = 0; index < count; index += 1) {
    const sequence = index + 1;
    const alertId = `${prefix}-H${sequence}`;
    alerts.push(fusedDetectorRecord(alertId, detectorOverrides));
    feedback.push({
      feedbackId: `${prefix}-FB${sequence}`,
      alertId,
      analystId: 'demo-analyst',
      timestamp: `2026-01-${String(sequence).padStart(2, '0')}T00:00:00Z`,
      eventType: 'feedback_submitted',
      feedbackType: feedbackTypes[index],
      reason: 'Synthetic demonstration feedback used only to exercise the real Stage 5 engine.',
      appliesToFutureSimilarAlerts: true,
    });
  }
  return { alerts, feedback };
}

function runScenario(currentAlert, historicalAlerts, feedbackEvents, config) {
  const result = adjustAlertsWithFeedback(
    [currentAlert],
    [],
    [],
    config,
    {
      historicalFeedbackEvents: feedbackEvents,
      similarityReferenceAlerts: [...historicalAlerts, currentAlert],
      useManualExceptionMemory: false,
    }
  );
  return buildAnalystAlert(result.adjustedAlerts[0]);
}

export function buildDemoScenarioArtifact(config) {
  const coldCurrent = fusedDetectorRecord('DEMO-COLD-1', {
    ml: {
      modelConfidence: 0.82,
      classProbabilities: { Benign: 0.18, DoS: 0.82 },
      predictionMargin: 0.64,
    },
  });

  const repeatedFp = historicalFixture(
    'DEMO-FP',
    3,
    ['mark_false_positive', 'mark_false_positive', 'mark_false_positive']
  );
  const fpCurrent = fusedDetectorRecord('DEMO-FP-CURRENT');

  const confirmedThreat = historicalFixture(
    'DEMO-TP',
    3,
    ['confirm_true_positive', 'confirm_true_positive', 'confirm_true_positive']
  );
  const mediumMlOverrides = {
    ml: {
      modelConfidence: 0.79,
      classProbabilities: { Benign: 0.21, DoS: 0.79 },
      predictionMargin: 0.58,
    },
  };
  confirmedThreat.alerts = confirmedThreat.alerts.map((alert) => fusedDetectorRecord(alert.id, mediumMlOverrides));
  const tpCurrent = fusedDetectorRecord('DEMO-TP-CURRENT', mediumMlOverrides);

  const conflict = historicalFixture(
    'DEMO-CONFLICT',
    4,
    ['mark_false_positive', 'mark_false_positive', 'confirm_true_positive', 'confirm_true_positive']
  );
  const thresholdMlOverrides = {
    ml: {
      modelConfidence: 0.8,
      classProbabilities: { Benign: 0.2, DoS: 0.8 },
      predictionMargin: 0.6,
    },
  };
  conflict.alerts = conflict.alerts.map((alert) => fusedDetectorRecord(alert.id, thresholdMlOverrides));
  const conflictCurrent = fusedDetectorRecord('DEMO-CONFLICT-CURRENT', thresholdMlOverrides);

  const guardrailDetectorOverrides = {
    signature: {
      signatureHit: true,
      signatureId: 'SIG-DEMO-CRITICAL-DOS',
      signatureAttackType: 'DoS',
      signatureSeverity: 'High',
      signaturePlainExplanation: 'Synthetic high-severity signature input for deterministic guardrail demonstration.',
    },
    ml: {
      predictedClassIndex: 0,
      predictedAttackType: 'Benign',
      modelConfidence: 0.95,
      classProbabilities: { Benign: 0.95, DoS: 0.05 },
      secondBestClass: 'DoS',
      predictionMargin: 0.9,
    },
  };
  const guardrail = historicalFixture(
    'DEMO-GUARDRAIL',
    3,
    ['mark_false_positive', 'mark_false_positive', 'mark_false_positive'],
    guardrailDetectorOverrides
  );
  const guardrailCurrent = fusedDetectorRecord('DEMO-GUARDRAIL-CURRENT', guardrailDetectorOverrides);

  const unavailableCurrent = fusedDetectorRecord('DEMO-ML-UNAVAILABLE', {
    signature: {
      signatureHit: true,
      signatureId: 'SIG-DEMO-DOS',
      signatureAttackType: 'DoS',
      signatureSeverity: 'High',
      signaturePlainExplanation: 'Synthetic signature input retained while ML prediction is unavailable.',
    },
    ml: {
      predictionStatus: 'unavailable',
      failureReason: 'invalid_numeric_feature_values',
      predictedClassIndex: null,
      predictedAttackType: null,
      modelConfidence: null,
      classProbabilities: null,
      secondBestClass: null,
      predictionMargin: null,
      mlExplanation: {
        status: 'unavailable',
        reason: 'prediction_unavailable',
        method: 'xgboost_native_treeshap_pred_contribs',
      },
    },
  });

  const scenarios = [
    {
      scenarioId: 'cold_start',
      title: 'Cold Start',
      purpose: 'No historical learning feedback is available, so priority remains equal to Detection Score.',
      alert: runScenario(coldCurrent, [], [], config),
    },
    {
      scenarioId: 'repeated_false_positive',
      title: 'Repeated False Positive',
      purpose: 'Three consistent similar false-positive events produce an eligible downward adjustment.',
      alert: runScenario(fpCurrent, repeatedFp.alerts, repeatedFp.feedback, config),
    },
    {
      scenarioId: 'confirmed_threat',
      title: 'Confirmed Threat',
      purpose: 'Three consistent similar confirmed-threat events produce an eligible upward adjustment.',
      alert: runScenario(tpCurrent, confirmedThreat.alerts, confirmedThreat.feedback, config),
    },
    {
      scenarioId: 'conflicting_history',
      title: 'Conflicting Historical Feedback',
      purpose: 'A tie between false-positive and confirmed-threat outcomes blocks adaptation.',
      alert: runScenario(conflictCurrent, conflict.alerts, conflict.feedback, config),
    },
    {
      scenarioId: 'guardrail_protection',
      title: 'Guardrail Protection',
      purpose: 'A proposed reduction is constrained by the configured Critical detection-score floor.',
      alert: runScenario(guardrailCurrent, guardrail.alerts, guardrail.feedback, config),
    },
    {
      scenarioId: 'ml_unavailable',
      title: 'ML Unavailable',
      purpose: 'Unavailable ML evidence remains explicit and is not interpreted as a Benign prediction.',
      alert: runScenario(unavailableCurrent, [], [], config),
    },
  ];

  const artifact = {
    schemaVersion: ANALYST_SCHEMA_VERSION,
    artifactType: DEMO_ARTIFACT_TYPE,
    generationMetadata: {
      generationMode: 'deterministic_stage4_stage5_demonstration',
      generatedAtPolicy: 'omitted_for_deterministic_artifact',
      formalEvaluationResult: false,
      automatedDetectionAuthority: 'stage-4/core/fusion-engine.js',
      adaptationAuthority: 'stage-5/core/feedback-engine.js',
      actualXgboostInference: false,
      manualExceptionMemoryEnabled: false,
    },
    summary: {
      scenarioCount: scenarios.length,
      successfulDownwardAdaptationCount: scenarios.filter((item) => item.alert.adaptation.appliedAdjustment < 0).length,
      successfulUpwardAdaptationCount: scenarios.filter((item) => item.alert.adaptation.appliedAdjustment > 0).length,
      noAdaptationCount: scenarios.filter((item) => !item.alert.adaptation.priorityAdjusted).length,
      conflictNoAdaptationCount: scenarios.filter((item) => item.alert.adaptation.conflictDetected).length,
      guardrailInterventionCount: scenarios.filter((item) => item.alert.adaptation.guardrailInterventions.length > 0).length,
      mlUnavailableScenarioCount: scenarios.filter((item) => !item.alert.mlEvidence.evidenceAvailable).length,
      groundTruthFieldCount: findForbiddenGroundTruthPaths(scenarios).length,
    },
    scenarios,
  };

  const validation = validateDemoArtifact(artifact);
  if (!validation.valid) throw new Error(`Invalid demo artifact: ${validation.errors.join(' ')}`);
  const privacyViolations = findPrivacyViolations(artifact);
  if (artifact.summary.groundTruthFieldCount > 0) throw new Error('Demo artifact contains evaluator ground truth.');
  if (privacyViolations.length > 0) throw new Error(`Demo privacy scan failed: ${privacyViolations.join(', ')}`);
  return artifact;
}

export function parseArgs(argv = process.argv.slice(2)) {
  const args = { config: defaultConfigPath, output: defaultOutputPath };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index + 1];
    if (argv[index] === '--config' && value) args.config = path.resolve(value);
    else if (argv[index] === '--output' && value) args.output = path.resolve(value);
    else throw new Error(`Unknown or incomplete argument: ${argv[index]}`);
    index += 1;
  }
  return args;
}

export function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const config = JSON.parse(fs.readFileSync(args.config, 'utf8'));
  const artifact = buildDemoScenarioArtifact(config);
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  console.log(`Demonstration scenarios written: ${artifact.summary.scenarioCount}`);
  console.log(`Output: ${args.output}`);
  return artifact;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
