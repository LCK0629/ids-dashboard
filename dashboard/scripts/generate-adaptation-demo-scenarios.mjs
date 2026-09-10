import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  ANALYST_SCHEMA_VERSION,
  DEMO_ARTIFACT_TYPE,
  findForbiddenGroundTruthPaths,
  validateAnalystAlert,
} from '../src/data-contract/analystDashboardContract.js';
import { buildAnalystAlert, findPrivacyViolations } from './export-dashboard-data.mjs';

const require = createRequire(import.meta.url);
const { adjustAlertsWithFeedback } = require('../../stage-5/core/feedback-engine.js');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..', '..');
const defaultConfigPath = path.join(repoRoot, 'stage-5', 'config', 'adaptation-config.json');
const defaultOutputPath = path.join(repoRoot, 'dashboard', 'src', 'data', 'adaptation-demo-scenarios.v1.json');

function baseAlert(id, overrides = {}) {
  return {
    id,
    flowFeatureSummary: {
      protocol: 'TCP',
      destinationPort: 443,
      flowDuration: 1200,
      totalFwdPackets: 24,
      totalBackwardPackets: 8,
      flowPacketsPerSecond: 26.7,
      flowBytesPerSecond: 4800,
      packetLengthMean: 180,
      synFlagCount: 2,
      ackFlagCount: 8,
    },
    signatureHit: false,
    signatureId: null,
    signatureAttackType: null,
    signatureSeverity: null,
    signaturePlainExplanation: null,
    matchedConditionsReadable: [],
    signatureTechnicalDetails: null,
    mlRecordPresent: true,
    mlPredictionStatus: 'available',
    mlEvidenceAvailable: true,
    mlFailureReason: null,
    mlSchemaMode: 'new',
    mlPredictedClassIndex: 4,
    mlPredictedAttackType: 'DoS',
    modelConfidence: 0.9,
    classProbabilities: { Benign: 0.1, DoS: 0.9 },
    secondBestClass: 'Benign',
    predictionMargin: 0.8,
    modelProvenance: null,
    mlExplanation: {
      status: 'unavailable',
      reason: 'demonstration_scenario_has_no_model_run',
      method: null,
    },
    mlThreatEvidenceScore: 90,
    fusionAttackType: 'DoS',
    fusionRiskScore: 80,
    fusionDecision: 'ML_ONLY_HIGH_CONFIDENCE',
    fusionEvidence: 'Deterministic demonstration input for Stage 5 adaptation behaviour.',
    requiresAnalystReview: true,
    fusionConfidenceLevel: 'High',
    ...overrides,
  };
}

function historicalFixture(prefix, count, feedbackTypes, alertOverrides = {}) {
  const alerts = [];
  const feedback = [];
  for (let index = 0; index < count; index += 1) {
    const sequence = index + 1;
    const alertId = `${prefix}-H${sequence}`;
    alerts.push(baseAlert(alertId, alertOverrides));
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
  const coldCurrent = baseAlert('DEMO-COLD-1', { fusionRiskScore: 72 });

  const repeatedFp = historicalFixture(
    'DEMO-FP',
    3,
    ['mark_false_positive', 'mark_false_positive', 'mark_false_positive']
  );
  const fpCurrent = baseAlert('DEMO-FP-CURRENT', { fusionRiskScore: 80 });

  const confirmedThreat = historicalFixture(
    'DEMO-TP',
    3,
    ['confirm_true_positive', 'confirm_true_positive', 'confirm_true_positive']
  );
  const tpCurrent = baseAlert('DEMO-TP-CURRENT', { fusionRiskScore: 60 });

  const conflict = historicalFixture(
    'DEMO-CONFLICT',
    4,
    ['mark_false_positive', 'mark_false_positive', 'confirm_true_positive', 'confirm_true_positive']
  );
  const conflictCurrent = baseAlert('DEMO-CONFLICT-CURRENT', { fusionRiskScore: 70 });

  const criticalOverrides = {
    fusionRiskScore: 85,
    fusionConfidenceLevel: 'Critical',
    signatureHit: true,
    signatureId: 'SIG-DEMO-CRITICAL-DOS',
    signatureAttackType: 'DoS',
    signatureSeverity: 'Critical',
    fusionDecision: 'SIGNATURE_ML_AGREE',
  };
  const guardrail = historicalFixture(
    'DEMO-GUARDRAIL',
    3,
    ['mark_false_positive', 'mark_false_positive', 'mark_false_positive'],
    criticalOverrides
  );
  const guardrailCurrent = baseAlert('DEMO-GUARDRAIL-CURRENT', criticalOverrides);

  const unavailableCurrent = baseAlert('DEMO-ML-UNAVAILABLE', {
    fusionRiskScore: 80,
    signatureHit: true,
    signatureId: 'SIG-DEMO-DOS',
    signatureAttackType: 'DoS',
    signatureSeverity: 'High',
    fusionDecision: 'SIGNATURE_ONLY_ML_UNAVAILABLE',
    mlRecordPresent: true,
    mlPredictionStatus: 'unavailable',
    mlEvidenceAvailable: false,
    mlFailureReason: 'invalid_numeric_feature_values',
    mlSchemaMode: 'new_unavailable',
    mlPredictedClassIndex: null,
    mlPredictedAttackType: null,
    modelConfidence: null,
    classProbabilities: null,
    secondBestClass: null,
    predictionMargin: null,
    mlThreatEvidenceScore: null,
    mlExplanation: {
      status: 'unavailable',
      reason: 'prediction_unavailable',
      method: 'xgboost_native_treeshap_pred_contribs',
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
      purpose: 'A proposed reduction is constrained by Critical signature/evidence protection.',
      alert: runScenario(guardrailCurrent, guardrail.alerts, guardrail.feedback, config),
    },
    {
      scenarioId: 'ml_unavailable',
      title: 'ML Unavailable',
      purpose: 'Unavailable ML evidence remains explicit and is not interpreted as a Benign prediction.',
      alert: runScenario(unavailableCurrent, [], [], config),
    },
  ];

  scenarios.forEach((scenario, index) => {
    const validation = validateAnalystAlert(scenario.alert, index);
    if (!validation.valid) throw new Error(`${scenario.scenarioId}: ${validation.errors.join(' ')}`);
  });

  const artifact = {
    schemaVersion: ANALYST_SCHEMA_VERSION,
    artifactType: DEMO_ARTIFACT_TYPE,
    generationMetadata: {
      generationMode: 'deterministic_stage5_core_demonstration',
      generatedAtPolicy: 'omitted_for_deterministic_artifact',
      formalEvaluationResult: false,
      scoringAuthority: 'stage-5/core/feedback-engine.js',
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
