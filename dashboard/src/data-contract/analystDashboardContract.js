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

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isScore(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100;
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

export function findForbiddenGroundTruthPaths(value, path = '$', matches = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findForbiddenGroundTruthPaths(item, `${path}[${index}]`, matches));
    return matches;
  }
  if (!isObject(value)) return matches;

  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (forbiddenGroundTruthKeys.has(key.toLowerCase())) matches.push(childPath);
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
    if (!ml.recordPresent && ml.predictionStatus !== 'missing_record') {
      errors.push(`${path}.mlEvidence without a record must use missing_record status.`);
    }
    if (ml.evidenceAvailable) {
      if (!ml.recordPresent) errors.push(`${path}.mlEvidence cannot be available without a record.`);
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
    } else if (ml.recordPresent && !isNonEmptyString(ml.failureReason)) {
      errors.push(`${path}.mlEvidence.failureReason is required for an unavailable record.`);
    }
    validateMlExplanation(ml.explanation, `${path}.mlEvidence.explanation`, errors);
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
  findForbiddenGroundTruthPaths(artifact).forEach((item) => errors.push(`Forbidden evaluator field: ${item}.`));
  return { valid: errors.length === 0, errors };
}

export function assertValidAnalystArtifact(artifact, options = {}) {
  const result = validateAnalystArtifact(artifact, options);
  if (!result.valid) throw new Error(`Invalid analyst dashboard artifact:\n${result.errors.join('\n')}`);
  return artifact;
}
