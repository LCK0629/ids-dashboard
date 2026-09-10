export const ML_CONFIDENCE_HELPER_TEXT = 'Uncalibrated classifier score; not certainty or threat risk.';
export const PREDICTION_MARGIN_HELPER_TEXT = 'Difference between the highest and second-highest class probability.';
export const SHAP_HELPER_TEXT = "SHAP values show how model features contributed to the predicted class's raw model margin.";
export const SHAP_NON_CAUSAL_TEXT = 'They are not probability changes, risk points, or causal effects.';

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function typeName(value, fallback = 'Unknown') {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

export function getDetectorStatePresentation(alert) {
  const automated = alert.automatedDetection;
  const signature = alert.signatureEvidence;
  const ml = alert.mlEvidence;
  const signatureType = typeName(signature.attackType, 'an attack pattern');
  const mlType = typeName(ml.predictedAttackType, 'an unavailable class');

  if (signature.hit && signature.attackType === 'Infiltration' && ml.predictedAttackType !== 'Infiltration') {
    return {
      key: 'infiltration_ml_limitation',
      label: 'Infiltration signature / ML coverage limitation',
      explanation: 'The current ML model does not cover Infiltration, so the available signature evidence is retained and analyst review is required.',
      tone: 'warning',
    };
  }
  if (automated.fusionDecision === 'SIGNATURE_ONLY_ML_BENIGN' && signature.hit) {
    return {
      key: 'signature_ml_benign_disagreement',
      label: 'Signature matched / ML predicts Benign',
      explanation: `The signature indicates ${signatureType}, while ML predicts Benign. This is conflicting evidence, not a conclusion that either detector is correct.`,
      tone: 'warning',
    };
  }
  if (automated.detectorState === 'signature_only' && signature.hit) {
    const mlContext = !ml.recordPresent
      ? 'No ML record is available.'
      : !ml.evidenceAvailable
        ? 'ML processing did not produce a usable prediction.'
        : `ML predicts ${mlType}, but it did not contribute attack evidence.`;
    return {
      key: 'signature_only',
      label: 'Signature-only evidence',
      explanation: `A signature indicates ${signatureType}. ${mlContext}`,
      tone: 'neutral',
    };
  }
  if (!ml.recordPresent) {
    return {
      key: 'ml_missing',
      label: signature.hit ? 'Signature evidence / ML record missing' : 'ML record missing',
      explanation: signature.hit
        ? `A signature indicates ${signatureType}, but no ML record is available for this detection.`
        : 'No ML record is available for this detection. Missing ML evidence is not a Benign prediction.',
      tone: 'warning',
    };
  }
  if (!ml.evidenceAvailable) {
    return {
      key: 'ml_unavailable',
      label: signature.hit ? 'Signature evidence / ML unavailable' : 'ML prediction unavailable',
      explanation: signature.hit
        ? `A signature indicates ${signatureType}. ML processing did not produce a usable prediction, so analyst review should rely on the available evidence.`
        : 'ML processing did not produce a usable prediction. Unavailable evidence does not mean the flow is Benign.',
      tone: 'warning',
    };
  }
  if (automated.detectorState === 'agreement') {
    return {
      key: 'agreement',
      label: 'Signature + ML agree',
      explanation: `Both detectors support ${typeName(automated.attackType)}. Agreement strengthens the automated evidence but is not proof of malicious activity.`,
      tone: 'positive',
    };
  }
  if (automated.detectorState === 'disagreement') {
    return {
      key: 'disagreement',
      label: 'Signature / ML disagree',
      explanation: `Signature indicates ${signatureType}; ML predicts ${mlType}. The conflict represents uncertainty and requires analyst interpretation.`,
      tone: 'warning',
    };
  }
  if (automated.detectorState === 'ml_only' || (!signature.hit && ml.predictedAttackType !== 'Benign')) {
    return {
      key: 'ml_only',
      label: 'ML-only evidence',
      explanation: `ML predicts ${mlType}, while no current prototype signature rule matched this flow.`,
      tone: 'neutral',
    };
  }
  return {
    key: 'no_detection_evidence',
    label: 'No current detection evidence',
    explanation: 'No current prototype signature rule matched and ML did not predict an attack class. This detector output is not ground truth.',
    tone: 'muted',
  };
}

export function getMlAvailabilityPresentation(ml) {
  if (!ml.recordPresent) {
    return {
      key: 'missing',
      label: 'No ML record available',
      explanation: 'No ML record is available for this detection. This is not a Benign prediction.',
    };
  }
  if (!ml.evidenceAvailable || ml.predictionStatus !== 'available') {
    return {
      key: 'unavailable',
      label: 'ML prediction unavailable',
      explanation: 'Unavailable ML evidence does not mean the flow is benign.',
    };
  }
  return {
    key: 'available',
    label: 'ML prediction available',
    explanation: `The model predicted ${typeName(ml.predictedAttackType)}.`,
  };
}

export function formatEvidenceReason(reason) {
  if (typeof reason !== 'string' || !reason.trim()) return 'Explanation unavailable';
  const knownReasons = {
    prediction_unavailable: 'Prediction unavailable, so TreeSHAP could not be generated.',
    tree_shap_generation_failed: 'TreeSHAP generation failed for this prediction.',
    additivity_check_failed: 'TreeSHAP additivity validation failed, so the explanation is not analyst-usable.',
    explanation_not_available: 'No TreeSHAP explanation is available for this prediction.',
    no_ml_record: 'No ML record is available to explain.',
  };
  return knownReasons[reason] || reason.replace(/[_-]+/g, ' ').replace(/^./, (letter) => letter.toUpperCase());
}

export function formatModelConfidence(value) {
  if (!isFiniteNumber(value)) return 'N/A';
  if (value >= 1) return '100.0%';
  if (value >= 0.999) return '99.9%+';
  return `${(value * 100).toFixed(1)}%`;
}

export function formatPredictionMargin(value) {
  if (!isFiniteNumber(value)) return 'N/A';
  return `${(value * 100).toFixed(1)} percentage points`;
}

export function formatFeatureValue(value) {
  if (value === null || value === undefined || value === '') return 'N/A';
  if (typeof value !== 'number') return String(value);
  if (!Number.isFinite(value)) return 'Invalid value';
  const magnitude = Math.abs(value);
  if ((magnitude >= 1_000_000) || (magnitude > 0 && magnitude < 0.001)) return value.toExponential(3);
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 4 }).format(value);
}

export function formatSignedShap(value) {
  if (!isFiniteNumber(value)) return 'N/A';
  if (Object.is(value, -0) || value === 0) return '0.0000';
  return `${value > 0 ? '+' : ''}${value.toFixed(4)}`;
}

export function normalizeShapWidths(features) {
  const magnitudes = features.map((feature) => (
    isFiniteNumber(feature.shapContribution) ? Math.abs(feature.shapContribution) : 0
  ));
  const maximum = Math.max(0, ...magnitudes);
  return features.map((feature, index) => ({
    ...feature,
    visualWidth: maximum === 0 ? 0 : (magnitudes[index] / maximum) * 100,
  }));
}

export function normalizeShapGroups(supporting, opposing) {
  const combined = normalizeShapWidths([...supporting, ...opposing]);
  return {
    supporting: combined.slice(0, supporting.length),
    opposing: combined.slice(supporting.length),
  };
}

export function shapDirectionLabel(direction, predictedClass) {
  const className = typeName(predictedClass, 'predicted class');
  return direction === 'opposes_prediction'
    ? `Opposes ${className} prediction`
    : `Supports ${className} prediction`;
}

export function getTreeShapPresentation(ml) {
  const explanation = ml.explanation;
  if (!explanation || explanation.status !== 'available') {
    return {
      available: false,
      title: 'TreeSHAP explanation unavailable',
      detail: formatEvidenceReason(explanation?.reason || ml.failureReason),
    };
  }
  return {
    available: true,
    title: `Feature contributions for ${typeName(explanation.explainedClass)} prediction`,
    detail: SHAP_HELPER_TEXT,
  };
}

export function shortenHash(value, leading = 10, trailing = 8) {
  if (typeof value !== 'string' || !value) return 'N/A';
  if (value.length <= leading + trailing + 1) return value;
  return `${value.slice(0, leading)}...${value.slice(-trailing)}`;
}
