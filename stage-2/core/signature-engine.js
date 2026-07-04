const fs = require('fs');

function loadJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function parseCsvLine(line) {
  const values = [];
  let current = '';
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const nextChar = line[index + 1];

    if (char === '"' && nextChar === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      values.push(current);
      current = '';
    } else {
      current += char;
    }
  }

  values.push(current);
  return values;
}

function loadCsvFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  const [headerLine, ...lines] = raw.split(/\r?\n/);
  const headers = parseCsvLine(headerLine);

  return lines.map((line) => {
    const values = parseCsvLine(line);
    return headers.reduce((record, header, index) => {
      const value = values[index] || '';
      const numericValue = Number(value);
      record[header] = value !== '' && !Number.isNaN(numericValue) ? numericValue : value;
      return record;
    }, {});
  });
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

  if (typeof expectedValue === 'number') {
    return Number(actualValue) === expectedValue;
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

const fieldLabels = {
  protocol: 'Protocol',
  destinationPort: 'Destination port',
  sourcePort: 'Source port',
  flowPacketsPerSecond: 'Flow packets per second',
  flowBytesPerSecond: 'Flow bytes per second',
  totalFwdPackets: 'Total forward packets',
  totalBwdPackets: 'Total backward packets',
  packetLengthMean: 'Mean packet length',
  fwdPacketLengthMean: 'Forward packet mean length',
  flowDuration: 'Flow duration',
};

const fieldUnits = {
  packetLengthMean: 'bytes',
  fwdPacketLengthMean: 'bytes',
  flowDuration: 'microseconds',
};

const plainExplanationByRuleId = {
  'SIG-WEB-ATTACK-FLOW': 'Suspicious web traffic was detected on an HTTP/HTTPS port. The flow used TCP, targeted a web service port, had relatively large packet sizes, and completed within a short time window. This pattern may indicate automated or abnormal web attack behaviour.',
  'SIG-SSH-BRUTE-FORCE': 'Suspicious SSH login-style traffic was detected. The flow targeted port 22 and showed repeated packets within a short time window, which may indicate brute-force authentication attempts.',
  'SIG-FTP-BRUTE-FORCE': 'Suspicious FTP login-style traffic was detected. The flow targeted port 21 and showed repeated packets within a short time window, which may indicate brute-force authentication attempts.',
  'SIG-DOS-HIGH-RATE-FLOW': 'High-rate traffic behaviour was detected. The flow showed unusually high packet or byte rates, which may indicate denial-of-service style activity.',
  'SIG-DDOS-HIGH-RATE-FLOW': 'High-rate traffic behaviour was detected. The flow showed unusually high packet or byte rates, which may indicate denial-of-service style activity.',
  'SIG-BOTNET-BEACON-FLOW': 'Botnet-like communication behaviour was detected. The flow pattern may indicate repeated or automated communication with a remote endpoint.',
  'SIG-INFILTRATION-LONG-FLOW': 'Long-duration traffic with sustained transfer behaviour was detected. This pattern may indicate infiltration-style activity, but it remains a prototype heuristic that should be reviewed with host and traffic context.',
};

function formatNumber(value) {
  return Number(value).toLocaleString('en-US');
}

function readableFieldName(field) {
  return fieldLabels[field] || field
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (char) => char.toUpperCase());
}

function formatCondition(field, expectedValue) {
  const label = readableFieldName(field);
  const unit = fieldUnits[field] ? ` ${fieldUnits[field]}` : '';

  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
    const parts = [];
    if ('equals' in expectedValue) {
      parts.push(`${label} is ${expectedValue.equals}`);
    }
    if ('oneOf' in expectedValue) {
      parts.push(`${label} is ${expectedValue.oneOf.join(' or ')}`);
    }
    if ('min' in expectedValue) {
      parts.push(`${label} is at least ${formatNumber(expectedValue.min)}${unit}`);
    }
    if ('max' in expectedValue) {
      parts.push(`${label} is at most ${formatNumber(expectedValue.max)}${unit}`);
    }
    return parts.join('; ');
  }

  return `${label} is ${expectedValue}`;
}

function buildMatchedConditionsReadable(signature) {
  return Object.entries(signature.condition).map(([field, value]) => formatCondition(field, value));
}

function buildPlainExplanation(signature) {
  return plainExplanationByRuleId[signature.id]
    || 'This flow matched a prototype signature rule based on observable traffic features. The match suggests suspicious behaviour, but the rule should be treated as a heuristic rather than definitive proof.';
}

function buildSignatureSummary(signature) {
  return `${signature.name} matched as a possible ${signature.predictedAttackType} pattern.`;
}

function buildSignatureTechnicalDetails(signature) {
  return {
    ruleId: signature.id,
    ruleName: signature.name,
    predictedAttackType: signature.predictedAttackType,
    severity: signature.severity,
    validationStatus: signature.validationStatus || 'unvalidated',
    rationale: Array.isArray(signature.rationale) ? signature.rationale.join(' ') : '',
    matchedConditions: buildMatchedConditionsReadable(signature),
  };
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
  const rationale = Array.isArray(signature.rationale) && signature.rationale.length > 0
    ? ` Rationale: ${signature.rationale[0]}`
    : '';
  const validationStatus = signature.validationStatus || 'unvalidated';

  return `Matched ${signature.name} as predicted ${signature.predictedAttackType} using observable flow conditions: ${conditionText}. Rule status: ${validationStatus}.${rationale}`;
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
        signatureSummary: null,
        signaturePlainExplanation: null,
        matchedConditionsReadable: [],
        signatureTechnicalDetails: null,
        signatureEvidence: 'No flow-based signature matched.',
      };
    }

    const matchedConditionsReadable = buildMatchedConditionsReadable(signature);

    return {
      ...alert,
      signatureHit: true,
      signatureId: signature.id,
      signatureName: signature.name,
      signatureAttackType: signature.predictedAttackType,
      signatureSeverity: signature.severity,
      signatureSummary: buildSignatureSummary(signature),
      signaturePlainExplanation: buildPlainExplanation(signature),
      matchedConditionsReadable,
      signatureTechnicalDetails: buildSignatureTechnicalDetails(signature),
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
      const evaluationAttackType = alert.trueAttackType || alert.attackType || 'Unknown';
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
  loadCsvFile,
  matchCondition,
  matchSignature,
  applySignatures,
  summariseSignatureResults,
};
