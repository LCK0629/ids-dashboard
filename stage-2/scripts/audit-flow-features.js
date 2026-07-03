const fs = require('fs');
const path = require('path');

const {
  loadCsvFile,
  loadJsonFile,
  matchCondition,
} = require('../core/signature-engine');

const repoRoot = path.resolve(__dirname, '..', '..');
const featureInputPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'flow-feature-sample.csv');
const groundTruthPath = path.join(repoRoot, 'stage-1', 'data', 'processed', 'ground-truth.json');
const rulesPath = path.join(repoRoot, 'stage-2', 'rules', 'flow-signatures.json');
const auditDir = path.join(repoRoot, 'stage-2', 'audit');

const featureSummaryJsonPath = path.join(auditDir, 'feature-distribution-summary.json');
const featureSummaryMarkdownPath = path.join(auditDir, 'feature-distribution-summary.md');
const boundaryJsonPath = path.join(auditDir, 'rule-boundary-analysis.json');
const boundaryMarkdownPath = path.join(auditDir, 'rule-boundary-analysis.md');
const reviewMatrixPath = path.join(auditDir, 'rule-review-matrix.md');

const numericFeatures = [
  'flowDuration',
  'totalFwdPackets',
  'totalBwdPackets',
  'flowBytesPerSecond',
  'flowPacketsPerSecond',
  'packetLengthMean',
  'fwdPacketLengthMean',
  'synFlagCount',
  'ackFlagCount',
  'finFlagCount',
  'rstFlagCount',
];

const confidenceByRule = {
  'SIG-FTP-BRUTE-FORCE': 'Moderate',
  'SIG-SSH-BRUTE-FORCE': 'Moderate',
  'SIG-DOS-HIGH-RATE-FLOW': 'Moderate',
  'SIG-DDOS-HIGH-RATE-FLOW': 'Moderate',
  'SIG-BOTNET-BEACON-FLOW': 'Experimental',
  'SIG-WEB-ATTACK-FLOW': 'Experimental',
  'SIG-INFILTRATION-LONG-FLOW': 'Weak',
};

const recommendationByRule = {
  'SIG-FTP-BRUTE-FORCE': 'Keep as prototype heuristic',
  'SIG-SSH-BRUTE-FORCE': 'Keep as prototype heuristic',
  'SIG-DOS-HIGH-RATE-FLOW': 'Keep but validate on held-out sample',
  'SIG-DDOS-HIGH-RATE-FLOW': 'Keep but validate on held-out sample',
  'SIG-BOTNET-BEACON-FLOW': 'Keep but validate on held-out sample',
  'SIG-WEB-ATTACK-FLOW': 'Keep but validate on held-out sample',
  'SIG-INFILTRATION-LONG-FLOW': 'Needs richer features',
};

const limitationByRule = {
  'SIG-FTP-BRUTE-FORCE': 'Cannot inspect FTP login payloads or failed login responses.',
  'SIG-SSH-BRUTE-FORCE': 'Cannot inspect SSH authentication failure details.',
  'SIG-DOS-HIGH-RATE-FLOW': 'High-rate legitimate traffic can also match this pattern.',
  'SIG-DDOS-HIGH-RATE-FLOW': 'A single flow row cannot prove distributed source behavior.',
  'SIG-BOTNET-BEACON-FLOW': 'Reliable botnet detection often needs host history, C2 indicators, or destination reputation.',
  'SIG-WEB-ATTACK-FLOW': 'Flow-level rules cannot inspect URLs, SQL strings, XSS payloads, or HTTP parameters.',
  'SIG-INFILTRATION-LONG-FLOW': 'Infiltration is context-dependent and difficult to detect with flow features alone.',
};

function percentile(sortedValues, p) {
  if (sortedValues.length === 0) {
    return 0;
  }

  const index = (sortedValues.length - 1) * p;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sortedValues[lower];
  }

  const weight = index - lower;
  return sortedValues[lower] * (1 - weight) + sortedValues[upper] * weight;
}

function summarizeValues(values) {
  const sorted = values.map(Number).filter((value) => !Number.isNaN(value)).sort((a, b) => a - b);
  const count = sorted.length;
  const sum = sorted.reduce((total, value) => total + value, 0);

  return {
    count,
    min: count ? sorted[0] : 0,
    p25: percentile(sorted, 0.25),
    median: percentile(sorted, 0.5),
    p75: percentile(sorted, 0.75),
    p90: percentile(sorted, 0.9),
    p95: percentile(sorted, 0.95),
    max: count ? sorted[count - 1] : 0,
    mean: count ? sum / count : 0,
  };
}

function groupByTrueAttackType(records) {
  return records.reduce((groups, record) => {
    const attackType = record.trueAttackType || 'Unknown';
    if (!groups[attackType]) {
      groups[attackType] = [];
    }
    groups[attackType].push(record);
    return groups;
  }, {});
}

function buildFeatureSummary(records) {
  const groups = groupByTrueAttackType(records);
  const summary = {};

  for (const [attackType, groupRecords] of Object.entries(groups)) {
    const destinationPortCounts = {};
    for (const record of groupRecords) {
      const port = String(record.destinationPort);
      destinationPortCounts[port] = (destinationPortCounts[port] || 0) + 1;
    }

    const featureStats = {};
    for (const feature of numericFeatures) {
      featureStats[feature] = summarizeValues(groupRecords.map((record) => record[feature]));
    }

    summary[attackType] = {
      totalRecords: groupRecords.length,
      destinationPortCounts,
      topDestinationPorts: Object.entries(destinationPortCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([port, count]) => ({ port, count })),
      numericFeatures: featureStats,
    };
  }

  return summary;
}

function conditionToText(field, expectedValue) {
  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
    return `${field} ${JSON.stringify(expectedValue)}`;
  }
  return `${field}=${expectedValue}`;
}

function getConditionValue(record, field) {
  return record[field];
}

function isConditionMatched(record, field, expectedValue) {
  const actualValue = getConditionValue(record, field);
  if (actualValue === undefined) {
    return false;
  }

  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
    if ('min' in expectedValue && Number(actualValue) < Number(expectedValue.min)) {
      return false;
    }
    if ('max' in expectedValue && Number(actualValue) > Number(expectedValue.max)) {
      return false;
    }
    if ('oneOf' in expectedValue && !expectedValue.oneOf.map(String).includes(String(actualValue))) {
      return false;
    }
    return true;
  }

  return String(actualValue).toLowerCase() === String(expectedValue).toLowerCase();
}

function isNumericCondition(expectedValue) {
  return expectedValue
    && typeof expectedValue === 'object'
    && !Array.isArray(expectedValue)
    && ('min' in expectedValue || 'max' in expectedValue)
    && !('oneOf' in expectedValue);
}

function isStrongCategoricalCondition(field, expectedValue) {
  if (field === 'protocol') {
    return false;
  }

  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue)) {
    return 'oneOf' in expectedValue;
  }

  return !isNumericCondition(expectedValue);
}

function isImportantNumericCondition(field) {
  return field !== 'totalBwdPackets';
}

function closeNumericBoundary(record, field, expectedValue) {
  const actualValue = getConditionValue(record, field);
  if (actualValue === undefined) {
    return null;
  }

  if (!isNumericCondition(expectedValue)) {
    return null;
  }

  const actualNumber = Number(actualValue);
  if (Number.isNaN(actualNumber)) {
    return null;
  }

  if ('min' in expectedValue) {
    const minValue = Number(expectedValue.min);
    if (actualNumber < minValue && actualNumber >= minValue * 0.8) {
      return `${field} close to min (${actualValue} vs ${expectedValue.min})`;
    }
  }

  if ('max' in expectedValue) {
    const maxValue = Number(expectedValue.max);
    if (actualNumber > maxValue && actualNumber <= maxValue * 1.2) {
      return `${field} close to max (${actualValue} vs ${expectedValue.max})`;
    }
  }

  return null;
}

function matchedCategoricalContext(record, field, expectedValue) {
  if (!isConditionMatched(record, field, expectedValue)) {
    return null;
  }

  if (expectedValue && typeof expectedValue === 'object' && !Array.isArray(expectedValue) && 'oneOf' in expectedValue) {
    return `${field} matched allowed value (${getConditionValue(record, field)})`;
  }

  if (!isNumericCondition(expectedValue)) {
    return `${field} matched (${getConditionValue(record, field)})`;
  }

  return null;
}

function nearMissDetails(record, rule) {
  const matchedContext = [];
  const closeThresholds = [];
  const closeImportantThresholds = [];
  let hasStrongCategoricalCondition = false;
  let hasStrongCategoricalMatch = false;

  for (const [field, expectedValue] of Object.entries(rule.condition)) {
    const context = matchedCategoricalContext(record, field, expectedValue);
    if (context) {
      matchedContext.push(context);
    }

    if (isStrongCategoricalCondition(field, expectedValue)) {
      hasStrongCategoricalCondition = true;
      if (context) {
        hasStrongCategoricalMatch = true;
      }
    }

    const closeReason = closeNumericBoundary(record, field, expectedValue);
    if (closeReason) {
      closeThresholds.push(closeReason);
      if (isImportantNumericCondition(field)) {
        closeImportantThresholds.push(closeReason);
      }
    }
  }

  return {
    matchedContext,
    closeThresholds,
    closeImportantThresholds,
    hasStrongCategoricalCondition,
    hasStrongCategoricalMatch,
    reasons: [...matchedContext, ...closeThresholds],
  };
}

function nearMissReasons(record, rule) {
  return nearMissDetails(record, rule).reasons;
}

function isNearMiss(record, rule) {
  if (matchCondition(record, rule.condition)) {
    return false;
  }

  const details = nearMissDetails(record, rule);
  if (details.closeImportantThresholds.length === 0) {
    return false;
  }

  if (details.hasStrongCategoricalCondition && !details.hasStrongCategoricalMatch) {
    return false;
  }

  return true;
}

function analyseRuleBoundaries(records, rules) {
  return rules.map((rule) => {
    const matchedRecords = records.filter((record) => matchCondition(record, rule.condition));
    const maliciousRecordsMatched = matchedRecords.filter((record) => record.groundTruth === 'malicious');
    const benignRecordsMatched = matchedRecords.filter((record) => record.groundTruth === 'benign');
    const coverageByTrueAttackType = {};

    for (const record of records) {
      const attackType = record.trueAttackType || 'Unknown';
      if (!coverageByTrueAttackType[attackType]) {
        coverageByTrueAttackType[attackType] = {
          total: 0,
          matched: 0,
          coverage: 0,
        };
      }
      coverageByTrueAttackType[attackType].total += 1;
    }

    for (const record of matchedRecords) {
      const attackType = record.trueAttackType || 'Unknown';
      coverageByTrueAttackType[attackType].matched += 1;
    }

    for (const coverage of Object.values(coverageByTrueAttackType)) {
      coverage.coverage = coverage.total === 0 ? 0 : coverage.matched / coverage.total;
    }

    const benignNearMisses = records
      .filter((record) => record.groundTruth === 'benign' && isNearMiss(record, rule))
      .map((record) => ({
        id: record.id,
        matchedOrCloseConditions: nearMissReasons(record, rule),
      }));

    const confidenceLevel = confidenceByRule[rule.id] || 'Experimental';
    const recommendation = recommendationByRule[rule.id] || 'Keep but validate on held-out sample';

    return {
      ruleId: rule.id,
      predictedAttackType: rule.predictedAttackType,
      currentConditions: rule.condition,
      totalRecordsMatched: matchedRecords.length,
      maliciousRecordsMatched: maliciousRecordsMatched.length,
      benignRecordsMatched: benignRecordsMatched.length,
      trueAttackTypeCoverage: coverageByTrueAttackType,
      benignFalseMatchCount: benignRecordsMatched.length,
      benignNearMissCount: benignNearMisses.length,
      benignNearMissExamples: benignNearMisses.slice(0, 5),
      confidenceLevel,
      interpretation: `${rule.name} matched ${matchedRecords.length} current sample records using feature-only conditions.`,
      limitation: limitationByRule[rule.id] || 'Prototype heuristic requires further validation.',
      actionRecommendation: recommendation,
    };
  });
}

function renderFeatureSummaryMarkdown(summary) {
  const lines = [
    '# Stage 2B Feature Distribution Summary',
    '',
    'Stage 2B is an audit, not a new detector. Ground truth is used only for analysis and reporting. Rules still run on feature-only input during detection.',
    '',
    'The audit supports rule interpretation, but it does not prove production readiness or globally optimal thresholds. Held-out validation is still required before making stronger claims.',
    '',
    '## Key Observations',
    '',
    '- Packet-rate and packet-count features are most relevant to DoS and DDoS rule families.',
    '- Destination port separates service-specific brute-force and web-flow rule families in the current sample.',
    '- Duration and byte-rate features are most relevant to Botnet and Infiltration-like rule families.',
    '- Some web and infiltration behavior can overlap with benign traffic in real deployments because payload and host context are unavailable.',
    '',
  ];

  for (const [attackType, data] of Object.entries(summary)) {
    lines.push(`## ${attackType}`);
    lines.push('');
    lines.push(`- Total records: ${data.totalRecords}`);
    lines.push(`- Top destination ports: ${data.topDestinationPorts.map((item) => `${item.port} (${item.count})`).join(', ') || 'none'}`);
    lines.push('');
    lines.push('| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |');
    lines.push('|---|---:|---:|---:|---:|---:|---:|---:|---:|');
    for (const [feature, stats] of Object.entries(data.numericFeatures)) {
      lines.push(`| \`${feature}\` | ${stats.min.toFixed(2)} | ${stats.p25.toFixed(2)} | ${stats.median.toFixed(2)} | ${stats.p75.toFixed(2)} | ${stats.p90.toFixed(2)} | ${stats.p95.toFixed(2)} | ${stats.max.toFixed(2)} | ${stats.mean.toFixed(2)} |`);
    }
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

function renderBoundaryMarkdown(analysis) {
  const lines = [
    '# Stage 2B Rule Boundary Analysis',
    '',
    'Stage 2B analyses current rule boundaries without changing thresholds. Ground truth is joined only for audit reporting.',
    '',
  ];

  for (const rule of analysis) {
    lines.push(`## ${rule.ruleId}`);
    lines.push('');
    lines.push(`- Predicted attack type: ${rule.predictedAttackType}`);
    lines.push(`- Total records matched: ${rule.totalRecordsMatched}`);
    lines.push(`- Malicious records matched: ${rule.maliciousRecordsMatched}`);
    lines.push(`- Benign records matched: ${rule.benignRecordsMatched}`);
    lines.push(`- Benign false match count: ${rule.benignFalseMatchCount}`);
    lines.push(`- Benign near-miss count: ${rule.benignNearMissCount}`);
    lines.push(`- Confidence level: ${rule.confidenceLevel}`);
    lines.push(`- Interpretation: ${rule.interpretation}`);
    lines.push(`- Limitation: ${rule.limitation}`);
    lines.push(`- Action recommendation: ${rule.actionRecommendation}`);
    lines.push('');
    lines.push('Current conditions:');
    lines.push('');
    for (const [field, expectedValue] of Object.entries(rule.currentConditions)) {
      lines.push(`- \`${conditionToText(field, expectedValue)}\``);
    }
    lines.push('');
    lines.push('True attack type coverage:');
    lines.push('');
    for (const [attackType, coverage] of Object.entries(rule.trueAttackTypeCoverage)) {
      if (coverage.matched > 0 || attackType === rule.predictedAttackType || attackType === 'Benign') {
        lines.push(`- ${attackType}: ${coverage.matched}/${coverage.total} (${(coverage.coverage * 100).toFixed(2)}%)`);
      }
    }
    lines.push('');
    lines.push('Benign near-miss examples:');
    lines.push('');
    if (rule.benignNearMissExamples.length === 0) {
      lines.push('- none');
    } else {
      for (const example of rule.benignNearMissExamples) {
        lines.push(`- ${example.id}: ${example.matchedOrCloseConditions.join('; ')}`);
      }
    }
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

function renderReviewMatrix(analysis) {
  const lines = [
    '# Stage 2B Rule Review Matrix',
    '',
    '| Rule ID | Predicted attack type | Evidence strength | Current sample result | Main limitation | Recommendation |',
    '|---|---|---|---|---|---|',
  ];

  for (const rule of analysis) {
    const result = `Matched ${rule.totalRecordsMatched} records with ${rule.benignFalseMatchCount} benign hits`;
    lines.push(`| \`${rule.ruleId}\` | ${rule.predictedAttackType} | ${rule.confidenceLevel} | ${result} | ${rule.limitation} | ${rule.actionRecommendation} |`);
  }

  lines.push('');
  lines.push('This matrix is for report support only. It does not tune thresholds or claim production readiness.');
  return `${lines.join('\n')}\n`;
}

function main() {
  const features = loadCsvFile(featureInputPath);
  const groundTruth = loadJsonFile(groundTruthPath);
  const rules = loadJsonFile(rulesPath);
  const records = features.map((record) => {
    const truth = groundTruth[record.id] || {};
    return {
      ...record,
      rawLabel: truth.rawLabel || null,
      trueAttackType: truth.mappedAttackType || 'Unknown',
      groundTruth: truth.groundTruth || 'unknown',
    };
  });

  const featureSummary = buildFeatureSummary(records);
  const boundaryAnalysis = analyseRuleBoundaries(records, rules);

  fs.mkdirSync(auditDir, { recursive: true });
  fs.writeFileSync(featureSummaryJsonPath, `${JSON.stringify(featureSummary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(featureSummaryMarkdownPath, renderFeatureSummaryMarkdown(featureSummary), 'utf8');
  fs.writeFileSync(boundaryJsonPath, `${JSON.stringify(boundaryAnalysis, null, 2)}\n`, 'utf8');
  fs.writeFileSync(boundaryMarkdownPath, renderBoundaryMarkdown(boundaryAnalysis), 'utf8');
  fs.writeFileSync(reviewMatrixPath, renderReviewMatrix(boundaryAnalysis), 'utf8');

  console.log(`Audited records: ${records.length}`);
  console.log(`True attack types: ${Object.keys(featureSummary).join(', ')}`);
  console.log(`Rules analysed: ${boundaryAnalysis.length}`);
  console.log(`Feature summary: ${featureSummaryMarkdownPath}`);
  console.log(`Rule boundary analysis: ${boundaryMarkdownPath}`);
  console.log(`Rule review matrix: ${reviewMatrixPath}`);
}

main();
