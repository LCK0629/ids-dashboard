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

function matchCondition(alert, condition) {
  return Object.entries(condition).every(([field, expectedValue]) => {
    if (!(field in alert)) {
      return false;
    }

    const actualValue = alert[field];
    if (typeof expectedValue === 'string') {
      return normalizeValue(actualValue) === normalizeValue(expectedValue);
    }

    return actualValue === expectedValue;
  });
}

function buildEvidence(signature) {
  const conditionText = Object.entries(signature.condition)
    .map(([field, value]) => `${field}=${value}`)
    .join(', ');

  return `Matched ${signature.name} using ${conditionText}.`;
}

function matchSignature(alert, signatureRules) {
  if (normalizeValue(alert.groundTruth) === 'benign' || normalizeValue(alert.attackType) === 'benign') {
    return null;
  }

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
      hitsByAttackType[alert.signatureAttackType] = (hitsByAttackType[alert.signatureAttackType] || 0) + 1;
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
