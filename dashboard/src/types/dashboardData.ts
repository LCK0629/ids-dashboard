export interface ModelProvenance {
  xgboostVersion?: string | null;
  modelArtifactVersion?: string | null;
  modelSha256?: string | null;
  featureSchemaSha256?: string | null;
  preprocessingConfigSha256?: string | null;
  labelMappingSha256?: string | null;
}

export interface ShapFeatureContribution {
  featureName: string;
  featureValue: number | string | null;
  shapContribution: number;
  direction: 'supports_prediction' | 'opposes_prediction';
}

export interface MlExplanation {
  status: 'available' | 'unavailable';
  reason?: string | null;
  method?: string | null;
  outputSpace?: 'raw_margin' | null;
  explainedClass?: string | null;
  explainedClassIndex?: number | null;
  baseValue?: number | null;
  rawModelMargin?: number | null;
  topSupportingFeatures: ShapFeatureContribution[];
  topOpposingFeatures: ShapFeatureContribution[];
  additivityCheck?: {
    passed: boolean;
    difference: number;
    tolerance: number;
  } | null;
}

export interface AnalystAlertV1 {
  identity: { id: string };
  flowFeatures: Record<string, string | number | null>;
  automatedDetection: {
    detectionScore: number;
    attackType: string;
    requiresAnalystReview: boolean;
    detectorState: string;
    fusionDecision: string;
    fusionExplanation: string;
    confidenceLevel: string | null;
  };
  signatureEvidence: {
    available: boolean;
    hit: boolean;
    ruleId: string | null;
    ruleName: string | null;
    attackType: string | null;
    severity: string | null;
    explanation: string | null;
    matchedConditions: string[];
    technicalDetail: {
      validationStatus: string | null;
      rationale: string | null;
    } | null;
  };
  mlEvidence: {
    recordPresent: boolean;
    predictionStatus: string;
    evidenceAvailable: boolean;
    failureReason: string | null;
    schemaMode: string;
    predictedClassIndex: number | null;
    predictedAttackType: string | null;
    modelConfidence: number | null;
    classProbabilities: Record<string, number> | null;
    secondBestClass: string | null;
    predictionMargin: number | null;
    threatEvidenceScore: number | null;
    modelProvenance: ModelProvenance | null;
    explanation: MlExplanation;
  };
  adaptation: {
    similarityMatched: boolean;
    similarityReason: string;
    matchedHistoricalFeedbackCount: number;
    matchedHistoricalFeedbackIds: string[];
    lowEvidenceCoverageRejectionCount: number;
    lowSimilarityRejectionCount: number;
    dominantHistoricalFeedback: string | null;
    historicalAgreementRatio: number;
    conflictDetected: boolean;
    eligible: boolean;
    eligibilityReason: string;
    proposedAdjustment: number;
    cappedAdjustment: number;
    appliedAdjustment: number;
    feedbackRecorded: boolean;
    priorityAdjusted: boolean;
    guardrailsApplied: string[];
    guardrailInterventions: Array<Record<string, unknown>>;
    operationalPriorityScore: number;
    source: string;
    explanation: string;
  };
  workflow: {
    requiresAnalystReviewBeforeFeedback: boolean;
    requiresAnalystReview: boolean;
    analystFeedbackStatus: string;
    matchedFeedbackId: string | null;
  };
}

export interface AnalystArtifactV1 {
  schemaVersion: 'ids-dashboard-analyst-v1';
  artifactType: 'analyst_operational_data';
  generationMetadata: Record<string, unknown>;
  summary: {
    recordCount: number;
    similarityMatchCount: number;
    adaptationEligibleCount: number;
    actualAdaptationCount: number;
    mlPredictionAvailableCount: number;
    mlPredictionUnavailableCount: number;
    treeShapAvailableCount: number;
    treeShapUnavailableCount: number;
    groundTruthFieldCount: number;
  };
  alerts: AnalystAlertV1[];
}

export interface EvaluatorSummaryArtifactV1 {
  schemaVersion: 'ids-dashboard-analyst-v1';
  artifactType: 'evaluator_summary';
  generationMetadata: Record<string, unknown>;
  fusionSummary: Record<string, unknown>;
  feedbackSummary: Record<string, unknown>;
}
