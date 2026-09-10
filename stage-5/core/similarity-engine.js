function getValueByPath(source, fieldPath) {
  return String(fieldPath || '').split('.').reduce((value, key) => {
    if (value === null || value === undefined || typeof value !== 'object') {
      return undefined;
    }
    return value[key];
  }, source);
}

function isAvailable(value) {
  return value !== undefined && value !== null && value !== '';
}

function normalizeValue(value) {
  if (typeof value === 'string') {
    return value.trim().toLowerCase();
  }
  return value;
}

function valuesEqual(left, right) {
  return normalizeValue(left) === normalizeValue(right);
}

function calculateSimilarity(currentAlert, historicalAlert, config) {
  const fields = (config && config.fields) || [];
  const threshold = Number((config && config.threshold) || 0);
  const reasons = [];
  const unavailableFields = [];
  const matchedFields = [];
  const differedFields = [];
  let totalAvailableWeight = 0;
  let matchedWeight = 0;

  for (const field of fields) {
    const path = field.path || field.name;
    const currentValue = getValueByPath(currentAlert, path);
    const historicalValue = getValueByPath(historicalAlert, path);
    const currentAvailable = isAvailable(currentValue);
    const historicalAvailable = isAvailable(historicalValue);

    if (!currentAvailable || !historicalAvailable) {
      unavailableFields.push(field.name || path);
      reasons.push(`${field.name || path} unavailable and excluded from similarity denominator.`);
      if (field.required) {
        return {
          score: 0,
          passed: false,
          threshold,
          matchedWeight: 0,
          totalAvailableWeight,
          matchedFields,
          differedFields,
          unavailableFields,
          reasons: [
            ...reasons,
            `${field.name || path} is required, so similarity failed.`,
          ],
          failureReason: 'missing_required_field',
        };
      }
      continue;
    }

    totalAvailableWeight += Number(field.weight || 0);
    if (valuesEqual(currentValue, historicalValue)) {
      matchedWeight += Number(field.weight || 0);
      matchedFields.push(field.name || path);
      reasons.push(`${field.name || path} matched.`);
    } else {
      differedFields.push(field.name || path);
      reasons.push(`${field.name || path} differed.`);
    }
  }

  const score = totalAvailableWeight === 0
    ? 0
    : Number((matchedWeight / totalAvailableWeight).toFixed(4));

  return {
    score,
    passed: score >= threshold,
    threshold,
    matchedWeight: Number(matchedWeight.toFixed(4)),
    totalAvailableWeight: Number(totalAvailableWeight.toFixed(4)),
    matchedFields,
    differedFields,
    unavailableFields,
    reasons,
    failureReason: score >= threshold ? null : 'below_similarity_threshold',
  };
}

module.exports = {
  getValueByPath,
  isAvailable,
  calculateSimilarity,
};
