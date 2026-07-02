const fs = require('fs');

function loadJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function normalizeValue(value) {
  if (typeof value === 'string') {
    return value.trim().toLowerCase();
  }
  return value;
}

function getValueByPath(source, fieldPath) {
  return fieldPath.split('.').reduce((value, key) => {
    if (value === null || value === undefined || typeof value !== 'object') {
      return undefined;
    }
    return value[key];
  }, source);
}

function compareValue(actualValue, expectedValue) {
  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
    if ('equals' in expectedValue && normalizeValue(actualValue) !== normalizeValue(expectedValue.equals)) {
      return false;
    }

    if ('min' in expectedValue && Number(actualValue) < Number(expectedValue.min)) {
      return false;
    }

    if ('max' in expectedValue && Number(actualValue) > Number(expectedValue.max)) {
      return false;
    }

    if ('oneOf' in expectedValue) {
      return expectedValue.oneOf
        .map((value) => normalizeValue(value))
        .includes(normalizeValue(actualValue));
    }

    return true;
  }

  if (typeof expectedValue === 'string') {
    return normalizeValue(actualValue) === normalizeValue(expectedValue);
  }

  return actualValue === expectedValue;
}

function matchCondition(alert, condition) {
  return Object.entries(condition).every(([field, expectedValue]) => {
    const actualValue = getValueByPath(alert, field);
    if (actualValue === undefined) {
      return false;
    }

    return compareValue(actualValue, expectedValue);
  });
}

function buildEvidence(signature) {
  const conditionText = Object.entries(signature.condition)
    .map(([field, value]) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return `${field} ${JSON.stringify(value)}`;
      }
      return `${field}=${value}`;
    })
    .join(', ');

  return `Matched ${signature.name} using ${conditionText}.`;
}

function matchSignature(alert, signatureRules) {
  return signatureRules.find((signature) => matchCondition(alert, signature.condition)) || null;
}

function applySignatures(alerts, signatureRules) {
  return alerts.map((alert) => {
    const signature = matchSignature(alert, signatureRules);

    if (!signature) {
      return {
        ...alert,
        signatureHit: false,
        signatureId: null,
        signatureName: null,
        signatureAttackType: null,
        signatureSeverity: null,
        signatureEvidence: 'No flow-based signature matched.',
      };
    }

    return {
      ...alert,
      signatureHit: true,
      signatureId: signature.id,
      signatureName: signature.name,
      signatureAttackType: signature.attackType,
      signatureSeverity: signature.severity,
      signatureEvidence: buildEvidence(signature),
    };
  });
}

function summariseSignatureResults(signedAlerts) {
  const totalAlerts = signedAlerts.length;
  const signatureHits = signedAlerts.filter((alert) => alert.signatureHit).length;
  const noSignatureHits = totalAlerts - signatureHits;
  const hitsBySignature = {};
  const hitsByAttackType = {};
  let benignAlertsWithSignatureHit = 0;

  for (const alert of signedAlerts) {
    if (alert.signatureHit) {
      hitsBySignature[alert.signatureId] = (hitsBySignature[alert.signatureId] || 0) + 1;
      const evaluationAttackType = alert.attackType || 'Unknown';
      hitsByAttackType[evaluationAttackType] = (hitsByAttackType[evaluationAttackType] || 0) + 1;
    }

    if (alert.signatureHit && normalizeValue(alert.groundTruth) === 'benign') {
      benignAlertsWithSignatureHit += 1;
    }
  }

  return {
    totalAlerts,
    signatureHits,
    noSignatureHits,
    signatureHitRate: totalAlerts === 0 ? 0 : signatureHits / totalAlerts,
    hitsBySignature,
    hitsByAttackType,
    benignAlertsWithSignatureHit,
  };
}

module.exports = {
  loadJsonFile,
  matchCondition,
  matchSignature,
  applySignatures,
  summariseSignatureResults,
};
