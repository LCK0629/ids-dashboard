export const ANALYST_SCHEMA_VERSION = 'ids-dashboard-analyst-v1';
export const ANALYST_ARTIFACT_TYPE = 'analyst_operational_data';
export const DEMO_ARTIFACT_TYPE = 'demonstration_scenarios';
export const EVALUATOR_ARTIFACT_TYPE = 'evaluator_summary';

const forbiddenGroundTruthKeys = new Set([
  'groundtruth',
  'groundtruthlabel',
  'trueattacktype',
  'mappedattacktype',
  'rawlabel',
  'actuallabel',
  'truelabel',
  'ismaliciousgroundtruth',
]);

const unavailablePredictionEvidenceFields = [
  'predictedClassIndex',
  'predictedAttackType',
  'modelConfidence',
  'classProbabilities',
  'secondBestClass',
  'predictionMargin',
  'threatEvidenceScore',
];

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isScore(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100;
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isNullish(value) {
  return value === null || value === undefined;
}

function normalizedKey(key) {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function validateFeatureContributions(features, path, errors) {
  if (!Array.isArray(features)) {
    errors.push(`${path} must be an array.`);
    return;
  }

  features.forEach((feature, index) => {
    const featurePath = `${path}[${index}]`;
    if (!isObject(feature)) {
      errors.push(`${featurePath} must be an object.`);
      return;
    }
    if (!isNonEmptyString(feature.featureName)) {
      errors.push(`${featurePath}.featureName must be a non-empty string.`);
    }
    if (typeof feature.shapContribution !== 'number' || !Number.isFinite(feature.shapContribution)) {
      errors.push(`${featurePath}.shapContribution must be finite.`);
    }
    if (!['supports_prediction', 'opposes_prediction'].includes(feature.direction)) {
      errors.push(`${featurePath}.direction must preserve the Stage 3 predicted-class direction.`);
    }
  });
}

function validateMlExplanation(explanation, path, errors) {
  if (!isObject(explanation) || !['available', 'unavailable'].includes(explanation.status)) {
    errors.push(`${path}.status must be available or unavailable.`);
    return;
  }

  if (explanation.status === 'unavailable') {
    if (!isNonEmptyString(explanation.reason)) {
      errors.push(`${path}.reason is required when explanation is unavailable.`);
    }
    return;
  }

  if (!isNonEmptyString(explanation.method)) errors.push(`${path}.method is required.`);
  if (explanation.outputSpace !== 'raw_margin') errors.push(`${path}.outputSpace must be raw_margin.`);
  if (!isNonEmptyString(explanation.explainedClass)) errors.push(`${path}.explainedClass is required.`);
  if (!Number.isInteger(explanation.explainedClassIndex) || explanation.explainedClassIndex < 0) {
    errors.push(`${path}.explainedClassIndex must be a non-negative integer.`);
  }
  if (typeof explanation.baseValue !== 'number' || !Number.isFinite(explanation.baseValue)) {
    errors.push(`${path}.baseValue must be finite.`);
  }
  if (typeof explanation.rawModelMargin !== 'number' || !Number.isFinite(explanation.rawModelMargin)) {
    errors.push(`${path}.rawModelMargin must be finite.`);
  }
  validateFeatureContributions(explanation.topSupportingFeatures, `${path}.topSupportingFeatures`, errors);
  validateFeatureContributions(explanation.topOpposingFeatures, `${path}.topOpposingFeatures`, errors);
  if (!isObject(explanation.additivityCheck) || explanation.additivityCheck.passed !== true) {
    errors.push(`${path}.additivityCheck must be present and passed.`);
  }
}

function validateUnavailableEvidenceFields(ml, path, errors, fields = unavailablePredictionEvidenceFields) {
  fields.forEach((field) => {
    if (!isNullish(ml[field])) {
      errors.push(`${path}.${field} must be null when ML prediction evidence is unavailable.`);
    }
  });
}

function validateMlExplanationConsistency(ml, path, errors) {
  const explanation = ml.explanation;
  if (!isObject(explanation) || explanation.status !== 'available') return;
  if (!ml.evidenceAvailable) {
    errors.push(`${path}.explanation cannot be available when ML prediction evidence is unavailable.`);
    return;
  }
  if (explanation.explainedClass !== ml.predictedAttackType) {
    errors.push(`${path}.explanation.explainedClass must equal predictedAttackType.`);
  }
  if (explanation.explainedClassIndex !== ml.predictedClassIndex) {
    errors.push(`${path}.explanation.explainedClassIndex must equal predictedClassIndex.`);
  }
}

export function findForbiddenGroundTruthPaths(value, path = '$', matches = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findForbiddenGroundTruthPaths(item, `${path}[${index}]`, matches));
    return matches;
  }
  if (!isObject(value)) return matches;

  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (forbiddenGroundTruthKeys.has(normalizedKey(key))) matches.push(childPath);
    findForbiddenGroundTruthPaths(child, childPath, matches);
  }
  return matches;
}

export function validateAnalystAlert(alert, index = 0) {
  const errors = [];
  const path = `alerts[${index}]`;
  if (!isObject(alert)) return { valid: false, errors: [`${path} must be an object.`] };
  if (!isObject(alert.identity) || !isNonEmptyString(alert.identity.id)) {
    errors.push(`${path}.identity.id must be a non-empty string.`);
  }
  if (!isObject(alert.automatedDetection)) {
    errors.push(`${path}.automatedDetection is required.`);
  } else {
    if (!isScore(alert.automatedDetection.detectionScore)) {
      errors.push(`${path}.automatedDetection.detectionScore must be between 0 and 100.`);
    }
    if (!isNonEmptyString(alert.automatedDetection.attackType)) {
      errors.push(`${path}.automatedDetection.attackType is required.`);
    }
    if (typeof alert.automatedDetection.requiresAnalystReview !== 'boolean') {
      errors.push(`${path}.automatedDetection.requiresAnalystReview must be boolean.`);
    }
  }
  if (!isObject(alert.adaptation) || !isScore(alert.adaptation.operationalPriorityScore)) {
    errors.push(`${path}.adaptation.operationalPriorityScore must be between 0 and 100.`);
  }
  if (!isObject(alert.mlEvidence)) {
    errors.push(`${path}.mlEvidence is required.`);
  } else {
    const ml = alert.mlEvidence;
    if (typeof ml.recordPresent !== 'boolean' || typeof ml.evidenceAvailable !== 'boolean') {
      errors.push(`${path}.mlEvidence must declare recordPresent and evidenceAvailable.`);
    }
    if (!isNonEmptyString(ml.predictionStatus)) {
      errors.push(`${path}.mlEvidence.predictionStatus is required.`);
    }
    if (!ml.recordPresent) {
      if (ml.evidenceAvailable) errors.push(`${path}.mlEvidence cannot be available without a record.`);
      if (ml.predictionStatus !== 'missing_record') {
        errors.push(`${path}.mlEvidence without a record must use missing_record status.`);
      }
      validateUnavailableEvidenceFields(ml, `${path}.mlEvidence`, errors);
      if (isObject(ml.explanation) && ml.explanation.status === 'available') {
        errors.push(`${path}.mlEvidence.explanation must be unavailable when no ML record exists.`);
      }
    } else if (!ml.evidenceAvailable) {
      if (ml.predictionStatus !== 'unavailable') {
        errors.push(`${path}.mlEvidence unavailable record must use unavailable status.`);
      }
      if (!isNonEmptyString(ml.failureReason)) {
        errors.push(`${path}.mlEvidence.failureReason is required for an unavailable record.`);
      }
      validateUnavailableEvidenceFields(ml, `${path}.mlEvidence`, errors);
      if (isObject(ml.explanation) && ml.explanation.status === 'available') {
        errors.push(`${path}.mlEvidence.explanation must be unavailable when prediction is unavailable.`);
      }
    } else {
      if (ml.predictionStatus !== 'available') {
        errors.push(`${path}.mlEvidence available prediction must use available status.`);
      }
      if (!Number.isInteger(ml.predictedClassIndex) || ml.predictedClassIndex < 0) {
        errors.push(`${path}.mlEvidence.predictedClassIndex must be a non-negative integer.`);
      }
      if (!isNonEmptyString(ml.predictedAttackType)) {
        errors.push(`${path}.mlEvidence.predictedAttackType is required when available.`);
      }
      if (typeof ml.modelConfidence !== 'number' || !Number.isFinite(ml.modelConfidence)
        || ml.modelConfidence < 0 || ml.modelConfidence > 1) {
        errors.push(`${path}.mlEvidence.modelConfidence must be between 0 and 1.`);
      }
      if (!isScore(ml.threatEvidenceScore)) {
        errors.push(`${path}.mlEvidence.threatEvidenceScore must be between 0 and 100.`);
      }
    }
    validateMlExplanation(ml.explanation, `${path}.mlEvidence.explanation`, errors);
    validateMlExplanationConsistency(ml, `${path}.mlEvidence`, errors);
  }

  const forbidden = findForbiddenGroundTruthPaths(alert, path);
  forbidden.forEach((item) => errors.push(`Forbidden evaluator field: ${item}.`));
  return { valid: errors.length === 0, errors };
}

export function validateAnalystArtifact(artifact, options = {}) {
  const expectedArtifactType = options.expectedArtifactType || ANALYST_ARTIFACT_TYPE;
  const errors = [];
  if (!isObject(artifact)) return { valid: false, errors: ['Artifact must be an object.'] };
  if (artifact.schemaVersion !== ANALYST_SCHEMA_VERSION) {
    errors.push(`Unsupported schemaVersion: ${String(artifact.schemaVersion)}.`);
  }
  if (artifact.artifactType !== expectedArtifactType) {
    errors.push(`Unexpected artifactType: ${String(artifact.artifactType)}.`);
  }
  if (!Array.isArray(artifact.alerts)) {
    errors.push('Artifact alerts must be an array.');
    return { valid: false, errors };
  }

  const seenIds = new Set();
  artifact.alerts.forEach((alert, index) => {
    const result = validateAnalystAlert(alert, index);
    errors.push(...result.errors);
    const id = alert && alert.identity && alert.identity.id;
    if (isNonEmptyString(id)) {
      if (seenIds.has(id)) errors.push(`Duplicate alert id: ${id}.`);
      seenIds.add(id);
    }
  });
  if (!isObject(artifact.summary)) {
    errors.push('Artifact summary must be an object.');
  } else {
    const expectedCounts = {
      recordCount: artifact.alerts.length,
      mlPredictionAvailableCount: artifact.alerts.filter((alert) => alert?.mlEvidence?.evidenceAvailable === true).length,
      mlPredictionUnavailableCount: artifact.alerts.filter((alert) => alert?.mlEvidence?.evidenceAvailable !== true).length,
      treeShapAvailableCount: artifact.alerts.filter((alert) => alert?.mlEvidence?.explanation?.status === 'available').length,
      treeShapUnavailableCount: artifact.alerts.filter((alert) => alert?.mlEvidence?.explanation?.status !== 'available').length,
      groundTruthFieldCount: 0,
    };
    Object.entries(expectedCounts).forEach(([key, expected]) => {
      if (artifact.summary[key] !== expected) {
        errors.push(`Artifact summary.${key} must equal ${expected}.`);
      }
    });
  }
  findForbiddenGroundTruthPaths(artifact).forEach((item) => errors.push(`Forbidden evaluator field: ${item}.`));
  return { valid: errors.length === 0, errors };
}

export function validateEvaluatorArtifact(artifact) {
  const errors = [];
  if (!isObject(artifact)) return { valid: false, errors: ['Evaluator artifact must be an object.'] };
  if (artifact.schemaVersion !== ANALYST_SCHEMA_VERSION) {
    errors.push(`Unsupported evaluator schemaVersion: ${String(artifact.schemaVersion)}.`);
  }
  if (artifact.artifactType !== EVALUATOR_ARTIFACT_TYPE) {
    errors.push(`Unexpected evaluator artifactType: ${String(artifact.artifactType)}.`);
  }
  if (!isObject(artifact.generationMetadata)) errors.push('Evaluator generationMetadata must be an object.');
  if (!isObject(artifact.fusionSummary)) errors.push('Evaluator fusionSummary must be an object.');
  if (!isObject(artifact.feedbackSummary)) errors.push('Evaluator feedbackSummary must be an object.');
  return { valid: errors.length === 0, errors };
}

export function validateStage5DashboardSourceRecord(record, index = 0) {
  const errors = [];
  const path = `source[${index}]`;
  if (!isObject(record)) return { valid: false, errors: [`${path} must be an object.`] };

  if (!isNonEmptyString(record.id)) errors.push(`${path}.id must be a non-empty string.`);
  if (!isScore(record.detectionScore)) errors.push(`${path}.detectionScore must be between 0 and 100.`);
  if (!isScore(record.operationalPriorityScore)) {
    errors.push(`${path}.operationalPriorityScore must be between 0 and 100.`);
  }
  if (typeof record.requiresAnalystReviewBeforeFeedback !== 'boolean') {
    errors.push(`${path}.requiresAnalystReviewBeforeFeedback must be boolean.`);
  }
  if (typeof record.requiresAnalystReview !== 'boolean') {
    errors.push(`${path}.requiresAnalystReview must be boolean.`);
  }

  if (typeof record.mlRecordPresent !== 'boolean') errors.push(`${path}.mlRecordPresent must be boolean.`);
  if (!isNonEmptyString(record.mlPredictionStatus)) errors.push(`${path}.mlPredictionStatus must be a non-empty string.`);
  if (typeof record.mlEvidenceAvailable !== 'boolean') errors.push(`${path}.mlEvidenceAvailable must be boolean.`);

  const sourceMl = {
    recordPresent: record.mlRecordPresent,
    predictionStatus: record.mlPredictionStatus,
    evidenceAvailable: record.mlEvidenceAvailable,
    failureReason: record.mlFailureReason,
    predictedClassIndex: record.mlPredictedClassIndex,
    predictedAttackType: record.mlPredictedAttackType,
    modelConfidence: record.modelConfidence,
    classProbabilities: record.classProbabilities,
    secondBestClass: record.secondBestClass,
    predictionMargin: record.predictionMargin,
    threatEvidenceScore: record.mlThreatEvidenceScore,
    explanation: record.mlExplanation,
  };

  if (record.mlRecordPresent === false) {
    if (record.mlEvidenceAvailable !== false) errors.push(`${path}.mlEvidenceAvailable must be false without an ML record.`);
    if (record.mlPredictionStatus !== 'missing_record') errors.push(`${path}.mlPredictionStatus must be missing_record without an ML record.`);
    validateUnavailableEvidenceFields(sourceMl, path, errors);
  } else if (record.mlRecordPresent === true && record.mlEvidenceAvailable === false) {
    if (record.mlPredictionStatus !== 'unavailable') errors.push(`${path}.mlPredictionStatus must be unavailable for an unavailable ML record.`);
    if (!isNonEmptyString(record.mlFailureReason)) errors.push(`${path}.mlFailureReason is required for an unavailable ML record.`);
    validateUnavailableEvidenceFields(sourceMl, path, errors);
  } else if (record.mlRecordPresent === true && record.mlEvidenceAvailable === true) {
    if (record.mlPredictionStatus !== 'available') errors.push(`${path}.mlPredictionStatus must be available when ML evidence is available.`);
    if (!Number.isInteger(record.mlPredictedClassIndex) || record.mlPredictedClassIndex < 0) {
      errors.push(`${path}.mlPredictedClassIndex must be a non-negative integer.`);
    }
    if (!isNonEmptyString(record.mlPredictedAttackType)) errors.push(`${path}.mlPredictedAttackType must be non-empty.`);
    if (!isFiniteNumber(record.modelConfidence) || record.modelConfidence < 0 || record.modelConfidence > 1) {
      errors.push(`${path}.modelConfidence must be between 0 and 1.`);
    }
    if (!isScore(record.mlThreatEvidenceScore)) errors.push(`${path}.mlThreatEvidenceScore must be between 0 and 100.`);
  }

  validateMlExplanation(record.mlExplanation, `${path}.mlExplanation`, errors);
  validateMlExplanationConsistency(sourceMl, path, errors);

  const adaptationFields = {
    similarityMatched: (value) => typeof value === 'boolean',
    matchedHistoricalFeedbackCount: (value) => Number.isInteger(value) && value >= 0,
    historicalAgreementRatio: (value) => isFiniteNumber(value) && value >= 0 && value <= 1,
    conflictDetected: (value) => typeof value === 'boolean',
    adaptationEligible: (value) => typeof value === 'boolean',
    proposedFeedbackAdjustment: isFiniteNumber,
    cappedFeedbackAdjustment: isFiniteNumber,
    feedbackAdjustment: isFiniteNumber,
    feedbackRecorded: (value) => typeof value === 'boolean',
    priorityAdjusted: (value) => typeof value === 'boolean',
    adaptationSource: isNonEmptyString,
  };
  Object.entries(adaptationFields).forEach(([field, validator]) => {
    if (!validator(record[field])) errors.push(`${path}.${field} is missing or invalid.`);
  });

  return { valid: errors.length === 0, errors };
}

export function assertValidStage5DashboardSource(records) {
  if (!Array.isArray(records)) throw new Error('Incompatible Stage 5 dashboard source: expected an array.');
  const errors = [];
  records.forEach((record, index) => {
    errors.push(...validateStage5DashboardSourceRecord(record, index).errors);
  });
  if (errors.length) {
    throw new Error(`Incompatible Stage 5 dashboard source:\n${errors.slice(0, 25).join('\n')}`);
  }
  return records;
}

export function assertValidAnalystArtifact(artifact, options = {}) {
  const result = validateAnalystArtifact(artifact, options);
  if (!result.valid) throw new Error(`Invalid analyst dashboard artifact:\n${result.errors.join('\n')}`);
  return artifact;
}
