import type { FeedbackAdjustedAlert } from '../types/alerts';
import { formatModelConfidenceScore, formatScore, isActionableAlert, isSuppressedOrResolved } from './alertFilters';

interface FeatureItem {
  label: string;
  value: string;
}

export interface FeatureGroup {
  title: string;
  items: FeatureItem[];
}

function displayValue(value: unknown, unit = ''): string {
  if (value === undefined || value === null || value === '') {
    return 'N/A';
  }
  if (typeof value === 'number') {
    const formatted = Number.isInteger(value)
      ? value.toLocaleString('en-US')
      : Number(value.toFixed(3)).toLocaleString('en-US');
    return `${formatted}${unit ? ` ${unit}` : ''}`;
  }
  return `${value}${unit ? ` ${unit}` : ''}`;
}

export function buildFeatureGroups(record: FeedbackAdjustedAlert): FeatureGroup[] {
  const feature = record.flowFeatureSummary || {};
  return [
    {
      title: 'Traffic Identity',
      items: [
        { label: 'Protocol', value: displayValue(feature.protocol) },
        { label: 'Source port', value: displayValue(feature.sourcePort) },
        { label: 'Destination port', value: displayValue(feature.destinationPort) },
      ],
    },
    {
      title: 'Volume',
      items: [
        { label: 'Total forward packets', value: displayValue(feature.totalFwdPackets) },
        { label: 'Total backward packets', value: displayValue(feature.totalBackwardPackets) },
        { label: 'Total forward bytes', value: displayValue(feature.totalLengthFwdPackets, 'bytes') },
        { label: 'Total backward bytes', value: displayValue(feature.totalLengthBwdPackets, 'bytes') },
      ],
    },
    {
      title: 'Rate',
      items: [
        { label: 'Flow packets per second', value: displayValue(feature.flowPacketsPerSecond) },
        { label: 'Flow bytes per second', value: displayValue(feature.flowBytesPerSecond) },
      ],
    },
    {
      title: 'Timing',
      items: [
        { label: 'Flow duration', value: displayValue(feature.flowDuration, 'microseconds') },
        { label: 'Flow IAT mean', value: displayValue(feature.flowIatMean) },
        { label: 'Flow IAT standard deviation', value: displayValue(feature.flowIatStd) },
      ],
    },
    {
      title: 'Packet Size',
      items: [
        { label: 'Packet length mean', value: displayValue(feature.packetLengthMean, 'bytes') },
        { label: 'Packet length maximum', value: displayValue(feature.packetLengthMax, 'bytes') },
        { label: 'Forward packet length mean', value: displayValue(feature.fwdPacketLengthMean, 'bytes') },
      ],
    },
    {
      title: 'TCP Flags',
      items: [
        { label: 'SYN flag count', value: displayValue(feature.synFlagCount) },
        { label: 'ACK flag count', value: displayValue(feature.ackFlagCount) },
        { label: 'PSH flag count', value: displayValue(feature.pshFlagCount) },
      ],
    },
  ];
}

export function buildFeatureInterpretation(record: FeedbackAdjustedAlert): string[] {
  const attackType = record.fusionAttackType || record.mlPredictedAttackType || 'Unknown';
  const interpretations = [
    'This record is interpreted using flow-level statistical features. The dashboard provides context for analyst review but does not inspect packet payloads.',
  ];

  if (attackType === 'DDoS' || attackType === 'DoS') {
    interpretations.push('High packet or byte rates can indicate denial-of-service style behaviour because many packets or bytes are observed in a short time window.');
    interpretations.push('Short or bursty flow duration may also support high-rate traffic interpretation.');
  } else if (attackType === 'Web Attack') {
    interpretations.push('Traffic targeting HTTP/HTTPS ports with unusual packet-size characteristics may indicate suspicious web request behaviour.');
  } else if (attackType === 'Brute Force') {
    interpretations.push('Repeated short TCP flows to login-related ports such as SSH or FTP may indicate authentication probing or brute-force behaviour.');
  } else if (attackType === 'Botnet') {
    interpretations.push('Repeated or automated communication patterns may indicate botnet-like command-and-control or beaconing behaviour.');
  } else if (attackType === 'Infiltration') {
    interpretations.push('Infiltration is difficult to identify using the current ML model because the current model artifacts do not include an Infiltration class.');
    interpretations.push('Investigation should rely on signature evidence, flow context, and analyst review.');
  } else if (attackType === 'Benign') {
    interpretations.push('The current fused result treats this record as low risk or benign. The record remains available for audit and evaluation.');
  }

  return interpretations;
}

export function relatedRuleFamily(record: FeedbackAdjustedAlert): string {
  const attackType = record.mlPredictedAttackType || record.fusionAttackType || 'Unknown';
  if (attackType === 'DDoS' || attackType === 'DoS') return 'high-rate flow rules';
  if (attackType === 'Web Attack') return 'web flow rules';
  if (attackType === 'Brute Force') return 'SSH/FTP brute-force rules';
  if (attackType === 'Botnet') return 'beacon / automated communication rules';
  if (attackType === 'Infiltration') return 'long-flow / suspicious transfer rules';
  return 'general flow-level heuristic rules';
}

export function signatureGapNote(record: FeedbackAdjustedAlert): string | null {
  if (record.signatureHit || !record.mlPredictedAttackType || record.mlPredictedAttackType === 'Benign') {
    return null;
  }

  return `No signature rule matched this record, but the ML model predicted suspicious behaviour. This is an ML-only detection case. The current prototype signature rules may be too narrow for this flow or may require packet/payload context that is not available in the flow dataset. Related rule family: ${relatedRuleFamily(record)}.`;
}

export function evidenceSource(record: FeedbackAdjustedAlert): string {
  const decision = record.fusionDecision || '';
  if (decision === 'SIGNATURE_ML_AGREE') return 'Signature + ML agree';
  if (decision === 'SIGNATURE_ML_DISAGREE' || decision === 'SIGNATURE_ONLY_ML_BENIGN') return 'Signature / ML disagree';
  if (decision.startsWith('SIGNATURE_ONLY')) return 'Signature-only';
  if (decision.startsWith('ML_ONLY')) return 'ML-only';
  if (decision.includes('LOW_RISK')) return 'Low-risk / benign';
  if (!record.signatureHit && !record.mlPredictedAttackType) return 'No detection input';
  if (record.signatureHit) return 'Signature-supported';
  return 'ML-only';
}

export function analystRecommendation(record: FeedbackAdjustedAlert): string {
  if (isSuppressedOrResolved(record) || Number(record.currentRiskScore || 0) === 0) {
    return 'No immediate action required. Retain this record for audit and evaluation.';
  }
  if (record.requiresAnalystReview) {
    return 'Review this record because it is currently promoted into the Active Alert Queue.';
  }
  if (Number(record.currentRiskScore || 0) >= 70) {
    return 'Prioritise this record due to its high current risk score.';
  }
  if (!record.signatureHit && record.mlPredictedAttackType && record.mlPredictedAttackType !== 'Benign') {
    return 'Treat this as ML-only evidence. Review the model prediction and flow features before making a decision.';
  }
  if (isActionableAlert(record)) {
    return 'Review this record if operational context suggests the suspicious pattern is unexpected.';
  }
  return 'No immediate review is required, but keep the record available for audit and evaluation.';
}

export function buildInvestigationTimeline(record: FeedbackAdjustedAlert): Array<[string, string]> {
  return [
    [
      'Flow observed',
      'This detection record represents one processed network flow. Key traffic features include destination port, packet rate, byte rate, packet size, timing, and TCP flags.',
    ],
    [
      'Signature check',
      record.signatureHit
        ? `A signature matched: ${record.signatureSummary || record.signatureId || 'prototype flow-level signature'}.`
        : 'No signature rule matched. This does not prove the flow is benign; it only means the current prototype signature rules did not match the observable flow conditions.',
    ],
    [
      'ML prediction',
      `The XGBoost model predicted ${record.mlPredictedAttackType || 'N/A'} with confidence score ${formatModelConfidenceScore(record.modelConfidence)}. The confidence score is uncalibrated and should not be interpreted as certainty.`,
    ],
    [
      'Fusion decision',
      `Fusion combined signature and ML evidence as ${record.fusionDecision || 'N/A'}, with fusion risk ${formatScore(record.fusionRiskScore)} and evidence source ${evidenceSource(record)}.`,
    ],
    [
      'Human feedback',
      `Feedback can adjust the current risk score to ${formatScore(record.currentRiskScore)} while guardrails prevent unsafe suppression. ${record.localFeedbackLabel || record.analystFeedbackStatus || 'No local feedback selected.'}`,
    ],
    ['Analyst recommendation', analystRecommendation(record)],
  ];
}
