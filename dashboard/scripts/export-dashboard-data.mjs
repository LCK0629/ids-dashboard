import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  ANALYST_ARTIFACT_TYPE,
  ANALYST_SCHEMA_VERSION,
  EVALUATOR_ARTIFACT_TYPE,
  assertValidAnalystArtifact,
  findForbiddenGroundTruthPaths,
} from '../src/data-contract/analystDashboardContract.js';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(scriptDir, '..', '..');

const defaultPaths = {
  analystInput: path.join(repoRoot, 'stage-5', 'outputs', 'feedback-adjusted-alerts.sample.json'),
  feedbackSummary: path.join(repoRoot, 'stage-5', 'evaluation', 'feedback-evaluation-summary.json'),
  fusionSummary: path.join(repoRoot, 'stage-4', 'evaluation', 'fusion-evaluation-summary.json'),
  adaptationConfig: path.join(repoRoot, 'stage-5', 'config', 'adaptation-config.json'),
  outputDir: path.join(repoRoot, 'dashboard', 'src', 'data'),
};

const flowFeatureKeys = [
  'protocol',
  'sourcePort',
  'destinationPort',
  'flowDuration',
  'totalFwdPackets',
  'totalBackwardPackets',
  'totalLengthFwdPackets',
  'totalLengthBwdPackets',
  'flowPacketsPerSecond',
  'flowBytesPerSecond',
  'packetLengthMean',
  'packetLengthMax',
  'fwdPacketLengthMean',
  'flowIatMean',
  'flowIatStd',
  'synFlagCount',
  'ackFlagCount',
  'pshFlagCount',
];

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

export function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

export function portableRepoPath(filePath) {
  const resolved = path.resolve(filePath);
  const relative = path.relative(repoRoot, resolved);
  if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
    return relative.split(path.sep).join('/');
  }
  return `external/${path.basename(resolved)}`;
}

function numberOrNull(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function stringOrNull(value) {
  return typeof value === 'string' && value.trim() ? value : null;
}

function copyStringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
}

function copyFlowFeatures(source = {}) {
  const output = {};
  for (const key of flowFeatureKeys) {
    const value = source[key];
    output[key] = typeof value === 'number' || typeof value === 'string' ? value : null;
  }
  return output;
}

function copyModelProvenance(source) {
  if (!source || typeof source !== 'object') return null;
  return {
    xgboostVersion: stringOrNull(source.xgboostVersion),
    modelArtifactVersion: stringOrNull(source.modelArtifactVersion),
    modelSha256: stringOrNull(source.modelSha256),
    featureSchemaSha256: stringOrNull(source.featureSchemaSha256),
    preprocessingConfigSha256: stringOrNull(source.preprocessingConfigSha256),
    labelMappingSha256: stringOrNull(source.labelMappingSha256),
  };
}

function copyClassProbabilities(source) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return null;
  const probabilities = {};
  for (const [className, probability] of Object.entries(source)) {
    if (typeof probability === 'number' && Number.isFinite(probability)) {
      probabilities[className] = probability;
    }
  }
  return probabilities;
}

function copyFeatureContributions(source) {
  if (!Array.isArray(source)) return [];
  return source.map((feature) => ({
    featureName: String(feature.featureName || ''),
    featureValue: typeof feature.featureValue === 'number' || typeof feature.featureValue === 'string'
      ? feature.featureValue
      : null,
    shapContribution: numberOrNull(feature.shapContribution),
    direction: stringOrNull(feature.direction),
  }));
}

function copyMlExplanation(source, mlFailureReason) {
  if (!source || typeof source !== 'object') {
    return {
      status: 'unavailable',
      reason: mlFailureReason || 'explanation_not_available',
      method: null,
      outputSpace: null,
      explainedClass: null,
      explainedClassIndex: null,
      baseValue: null,
      rawModelMargin: null,
      topSupportingFeatures: [],
      topOpposingFeatures: [],
      additivityCheck: null,
    };
  }

  return {
    status: source.status === 'available' ? 'available' : 'unavailable',
    reason: stringOrNull(source.reason),
    method: stringOrNull(source.method),
    outputSpace: stringOrNull(source.outputSpace),
    explainedClass: stringOrNull(source.explainedClass),
    explainedClassIndex: numberOrNull(source.explainedClassIndex),
    baseValue: numberOrNull(source.baseValue),
    rawModelMargin: numberOrNull(source.rawModelMargin),
    topSupportingFeatures: copyFeatureContributions(source.topSupportingFeatures),
    topOpposingFeatures: copyFeatureContributions(source.topOpposingFeatures),
    additivityCheck: source.additivityCheck && typeof source.additivityCheck === 'object'
      ? {
        passed: source.additivityCheck.passed === true,
        difference: numberOrNull(source.additivityCheck.difference),
        tolerance: numberOrNull(source.additivityCheck.tolerance),
      }
      : null,
  };
}

function detectorState(alert) {
  const decision = String(alert.fusionDecision || 'UNKNOWN');
  if (decision === 'SIGNATURE_ML_AGREE') return 'agreement';
  if (decision.includes('DISAGREE') || decision === 'SIGNATURE_ONLY_ML_BENIGN') return 'disagreement';
  if (decision.startsWith('ML_ONLY')) return 'ml_only';
  if (decision.startsWith('SIGNATURE_ONLY')) return 'signature_only';
  if (alert.mlRecordPresent && !alert.mlEvidenceAvailable) return 'ml_unavailable';
  return 'no_detection_evidence';
}

export function buildAnalystAlert(alert) {
  const detectionScore = numberOrNull(alert.detectionScore);
  const operationalPriorityScore = numberOrNull(alert.operationalPriorityScore);
  const mlFailureReason = stringOrNull(alert.mlFailureReason);
  const signatureTechnical = alert.signatureTechnicalDetails && typeof alert.signatureTechnicalDetails === 'object'
    ? alert.signatureTechnicalDetails
    : null;

  return {
    identity: {
      id: typeof alert.id === 'string' ? alert.id : String(alert.id || ''),
    },
    flowFeatures: copyFlowFeatures(alert.flowFeatureSummary),
    automatedDetection: {
      detectionScore,
      attackType: stringOrNull(alert.fusionAttackType) || 'Unknown',
      requiresAnalystReview: Boolean(alert.requiresAnalystReviewBeforeFeedback),
      detectorState: detectorState(alert),
      fusionDecision: stringOrNull(alert.fusionDecision) || 'UNKNOWN',
      fusionExplanation: stringOrNull(alert.fusionEvidence) || 'No fusion explanation available.',
      confidenceLevel: stringOrNull(alert.fusionConfidenceLevel),
    },
    signatureEvidence: {
      available: typeof alert.signatureHit === 'boolean',
      hit: alert.signatureHit === true,
      ruleId: stringOrNull(signatureTechnical?.ruleId || alert.signatureId),
      ruleName: stringOrNull(signatureTechnical?.ruleName || alert.signatureName),
      attackType: stringOrNull(signatureTechnical?.predictedAttackType || alert.signatureAttackType),
      severity: stringOrNull(signatureTechnical?.severity || alert.signatureSeverity),
      explanation: stringOrNull(alert.signaturePlainExplanation || alert.signatureSummary || alert.signatureEvidence),
      matchedConditions: copyStringArray(
        Array.isArray(alert.matchedConditionsReadable)
          ? alert.matchedConditionsReadable
          : signatureTechnical?.matchedConditions
      ),
      technicalDetail: signatureTechnical
        ? {
          validationStatus: stringOrNull(signatureTechnical.validationStatus),
          rationale: stringOrNull(signatureTechnical.rationale),
        }
        : null,
    },
    mlEvidence: {
      recordPresent: alert.mlRecordPresent === true,
      predictionStatus: stringOrNull(alert.mlPredictionStatus) || 'missing_record',
      evidenceAvailable: alert.mlEvidenceAvailable === true,
      failureReason: mlFailureReason,
      schemaMode: stringOrNull(alert.mlSchemaMode) || 'unknown',
      predictedClassIndex: numberOrNull(alert.mlPredictedClassIndex),
      predictedAttackType: stringOrNull(alert.mlPredictedAttackType),
      modelConfidence: numberOrNull(alert.modelConfidence),
      classProbabilities: copyClassProbabilities(alert.classProbabilities),
      secondBestClass: stringOrNull(alert.secondBestClass),
      predictionMargin: numberOrNull(alert.predictionMargin),
      threatEvidenceScore: numberOrNull(alert.mlThreatEvidenceScore),
      modelProvenance: copyModelProvenance(alert.modelProvenance),
      explanation: copyMlExplanation(alert.mlExplanation, mlFailureReason),
    },
    adaptation: {
      similarityMatched: alert.similarityMatched === true,
      similarityReason: stringOrNull(alert.similarityReason) || 'No similarity result available.',
      matchedHistoricalFeedbackCount: Number.isInteger(alert.matchedHistoricalFeedbackCount)
        ? alert.matchedHistoricalFeedbackCount
        : 0,
      matchedHistoricalFeedbackIds: copyStringArray(alert.matchedHistoricalFeedbackIds),
      lowEvidenceCoverageRejectionCount: Number.isInteger(alert.lowEvidenceCoverageCount)
        ? alert.lowEvidenceCoverageCount
        : 0,
      lowSimilarityRejectionCount: Number.isInteger(alert.lowSimilarityCount) ? alert.lowSimilarityCount : 0,
      dominantHistoricalFeedback: stringOrNull(alert.dominantHistoricalFeedback),
      historicalAgreementRatio: numberOrNull(alert.historicalAgreementRatio) ?? 0,
      conflictDetected: alert.conflictDetected === true,
      eligible: alert.adaptationEligible === true,
      eligibilityReason: stringOrNull(alert.adaptationEligibilityReason) || 'No adaptation eligibility result available.',
      proposedAdjustment: numberOrNull(alert.proposedFeedbackAdjustment) ?? 0,
      cappedAdjustment: numberOrNull(alert.cappedFeedbackAdjustment) ?? 0,
      appliedAdjustment: numberOrNull(alert.feedbackAdjustment) ?? 0,
      feedbackRecorded: alert.feedbackRecorded === true,
      priorityAdjusted: alert.priorityAdjusted === true,
      guardrailsApplied: copyStringArray(alert.feedbackGuardrailsApplied),
      guardrailInterventions: Array.isArray(alert.guardrailInterventions)
        ? alert.guardrailInterventions.map((intervention) => ({
          code: stringOrNull(intervention.code),
          configuredValue: intervention.configuredValue ?? null,
          originalValue: intervention.originalValue ?? null,
          appliedValue: intervention.appliedValue ?? null,
        }))
        : [],
      operationalPriorityScore,
      source: stringOrNull(alert.adaptationSource) || 'none',
      explanation: stringOrNull(alert.adaptationExplanation || alert.feedbackReason)
        || 'No historical feedback adaptation was applied.',
    },
    workflow: {
      requiresAnalystReviewBeforeFeedback: Boolean(alert.requiresAnalystReviewBeforeFeedback),
      requiresAnalystReview: Boolean(alert.requiresAnalystReview),
      analystFeedbackStatus: stringOrNull(alert.analystFeedbackStatus) || 'unchanged',
      matchedFeedbackId: stringOrNull(alert.matchedFeedbackId),
    },
  };
}

export function sortAnalystAlerts(alerts) {
  return [...alerts].sort((left, right) => {
    const priorityDifference = right.adaptation.operationalPriorityScore - left.adaptation.operationalPriorityScore;
    if (priorityDifference !== 0) return priorityDifference;
    const reviewDifference = Number(right.workflow.requiresAnalystReview) - Number(left.workflow.requiresAnalystReview);
    if (reviewDifference !== 0) return reviewDifference;
    return left.identity.id.localeCompare(right.identity.id, undefined, { numeric: true });
  });
}

function countArtifactEvidence(alerts) {
  return {
    recordCount: alerts.length,
    similarityMatchCount: alerts.filter((alert) => alert.adaptation.similarityMatched).length,
    adaptationEligibleCount: alerts.filter((alert) => alert.adaptation.eligible).length,
    actualAdaptationCount: alerts.filter((alert) => alert.adaptation.priorityAdjusted).length,
    mlPredictionAvailableCount: alerts.filter((alert) => alert.mlEvidence.evidenceAvailable).length,
    mlPredictionUnavailableCount: alerts.filter((alert) => !alert.mlEvidence.evidenceAvailable).length,
    treeShapAvailableCount: alerts.filter((alert) => alert.mlEvidence.explanation.status === 'available').length,
    treeShapUnavailableCount: alerts.filter((alert) => alert.mlEvidence.explanation.status !== 'available').length,
    groundTruthFieldCount: findForbiddenGroundTruthPaths(alerts).length,
  };
}

export function buildAnalystArtifact(stage5Alerts, metadata = {}) {
  if (!Array.isArray(stage5Alerts)) throw new Error('Stage 5 analyst input must be an array.');
  const alerts = sortAnalystAlerts(stage5Alerts.map(buildAnalystAlert));
  const artifact = {
    schemaVersion: ANALYST_SCHEMA_VERSION,
    artifactType: ANALYST_ARTIFACT_TYPE,
    generationMetadata: {
      generationMode: metadata.generationMode || 'formal_frozen_calibration_held_out',
      generatedAtPolicy: 'omitted_for_deterministic_artifact',
      deterministicOrdering: 'operationalPriorityScore desc, requiresAnalystReview desc, id asc',
      sourcePaths: metadata.sourcePaths || {},
      sourceHashes: metadata.sourceHashes || {},
      modelSha256: metadata.modelSha256 || null,
      adaptationConfigSha256: metadata.adaptationConfigSha256 || null,
      publicationContext: 'offline_research_data_prototype',
    },
    summary: countArtifactEvidence(alerts),
    alerts,
  };
  assertValidAnalystArtifact(artifact);
  return artifact;
}

export function findPrivacyViolations(value, pathLabel = '$', findings = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findPrivacyViolations(item, `${pathLabel}[${index}]`, findings));
    return findings;
  }
  if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => findPrivacyViolations(child, `${pathLabel}.${key}`, findings));
    return findings;
  }
  if (typeof value !== 'string') return findings;

  const patterns = [
    /[A-Za-z]:[\\/]Users[\\/]/i,
    /\/Users\//i,
    /\/home\//i,
    /OneDrive/i,
    /github_pat_[A-Za-z0-9_]+/,
    /ghp_[A-Za-z0-9]+/,
    /AKIA[0-9A-Z]{16}/,
  ];
  if (patterns.some((pattern) => pattern.test(value))) findings.push(pathLabel);
  return findings;
}

export function parseArgs(argv = process.argv.slice(2)) {
  const args = { ...defaultPaths, demoScenarios: null };
  const options = {
    '--analyst-input': 'analystInput',
    '--feedback-summary': 'feedbackSummary',
    '--fusion-summary': 'fusionSummary',
    '--adaptation-config': 'adaptationConfig',
    '--demo-scenarios': 'demoScenarios',
    '--output-dir': 'outputDir',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = options[argv[index]];
    if (!key || !argv[index + 1]) throw new Error(`Unknown or incomplete argument: ${argv[index]}`);
    args[key] = path.resolve(argv[index + 1]);
    index += 1;
  }
  return args;
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function exportDashboardData(args) {
  const stage5Alerts = readJson(args.analystInput);
  const feedbackSummary = readJson(args.feedbackSummary);
  const fusionSummary = readJson(args.fusionSummary);
  const adaptationConfigSha256 = sha256File(args.adaptationConfig);
  const firstProvenance = stage5Alerts.find((alert) => alert.modelProvenance)?.modelProvenance || {};
  const sourcePaths = {
    analystInput: portableRepoPath(args.analystInput),
    feedbackSummary: portableRepoPath(args.feedbackSummary),
    fusionSummary: portableRepoPath(args.fusionSummary),
    adaptationConfig: portableRepoPath(args.adaptationConfig),
  };
  const sourceHashes = {
    analystInputSha256: sha256File(args.analystInput),
    feedbackSummarySha256: sha256File(args.feedbackSummary),
    fusionSummarySha256: sha256File(args.fusionSummary),
  };
  const analystArtifact = buildAnalystArtifact(stage5Alerts, {
    generationMode: feedbackSummary.evaluationSplit || 'formal_frozen_calibration_held_out',
    sourcePaths,
    sourceHashes,
    modelSha256: firstProvenance.modelSha256 || null,
    adaptationConfigSha256,
  });
  const evaluatorArtifact = {
    schemaVersion: ANALYST_SCHEMA_VERSION,
    artifactType: EVALUATOR_ARTIFACT_TYPE,
    generationMetadata: {
      generatedAtPolicy: 'omitted_for_deterministic_artifact',
      sourcePaths: {
        feedbackSummary: sourcePaths.feedbackSummary,
        fusionSummary: sourcePaths.fusionSummary,
      },
      sourceHashes: {
        feedbackSummarySha256: sourceHashes.feedbackSummarySha256,
        fusionSummarySha256: sourceHashes.fusionSummarySha256,
      },
      groundTruthBoundary: 'aggregate_evaluator_metrics_only',
    },
    fusionSummary,
    feedbackSummary,
  };

  const privacyViolations = [
    ...findPrivacyViolations(analystArtifact).map((item) => `analyst${item}`),
    ...findPrivacyViolations(evaluatorArtifact).map((item) => `evaluator${item}`),
  ];
  if (privacyViolations.length) throw new Error(`Privacy scan failed: ${privacyViolations.join(', ')}`);
  fs.mkdirSync(args.outputDir, { recursive: true });
  const analystOutput = path.join(args.outputDir, 'analyst-alerts.v1.json');
  const evaluatorOutput = path.join(args.outputDir, 'evaluator-summary.v1.json');
  const manifestOutput = path.join(args.outputDir, 'dashboard-data-manifest.v1.json');
  writeJson(analystOutput, analystArtifact);
  writeJson(evaluatorOutput, evaluatorArtifact);

  const manifest = {
    schemaVersion: ANALYST_SCHEMA_VERSION,
    artifactType: 'dashboard_data_manifest',
    generatedAtPolicy: 'omitted_for_deterministic_artifact',
    generationMode: 'reproducible_stage3_stage4_stage5_export',
    artifacts: {
      analystOperationalData: {
        path: portableRepoPath(analystOutput),
        sha256: sha256File(analystOutput),
        recordCount: analystArtifact.summary.recordCount,
      },
      evaluatorSummary: {
        path: portableRepoPath(evaluatorOutput),
        sha256: sha256File(evaluatorOutput),
      },
      demonstrationScenarios: args.demoScenarios && fs.existsSync(args.demoScenarios)
        ? {
          path: portableRepoPath(args.demoScenarios),
          sha256: sha256File(args.demoScenarios),
          scenarioCount: readJson(args.demoScenarios).summary?.scenarioCount ?? null,
        }
        : null,
    },
    sources: {
      paths: sourcePaths,
      hashes: sourceHashes,
      modelSha256: firstProvenance.modelSha256 || null,
      adaptationConfigSha256,
    },
    privacy: {
      groundTruthFieldCountInAnalystArtifact: analystArtifact.summary.groundTruthFieldCount,
      localPathOrCredentialFindingCount: privacyViolations.length,
      networkIdentifierInventory: [
        'protocol',
        'sourcePort',
        'destinationPort',
        'No source or destination IP address is exported by analyst schema v1.',
      ],
      publicationContext: 'offline_research_data_prototype',
    },
  };
  const manifestPrivacyViolations = findPrivacyViolations(manifest);
  if (manifestPrivacyViolations.length) {
    throw new Error(`Manifest privacy scan failed: ${manifestPrivacyViolations.join(', ')}`);
  }
  writeJson(manifestOutput, manifest);

  return { analystArtifact, evaluatorArtifact, manifest, paths: { analystOutput, evaluatorOutput, manifestOutput } };
}

export function main(argv = process.argv.slice(2)) {
  const result = exportDashboardData(parseArgs(argv));
  console.log(`Analyst records exported: ${result.analystArtifact.summary.recordCount}`);
  console.log(`ML available/unavailable: ${result.analystArtifact.summary.mlPredictionAvailableCount}/${result.analystArtifact.summary.mlPredictionUnavailableCount}`);
  console.log(`TreeSHAP available/unavailable: ${result.analystArtifact.summary.treeShapAvailableCount}/${result.analystArtifact.summary.treeShapUnavailableCount}`);
  console.log(`Ground-truth fields in analyst artifact: ${result.analystArtifact.summary.groundTruthFieldCount}`);
  console.log(`Analyst artifact: ${result.paths.analystOutput}`);
  console.log(`Manifest: ${result.paths.manifestOutput}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
