# Analyst Dashboard Data Contract

## Version

The React dashboard consumes `ids-dashboard-analyst-v1` from:

```txt
dashboard/src/data/analyst-alerts.v1.json
```

The envelope contains generation metadata, a compact summary, and explicitly whitelisted analyst records. Runtime validation rejects unsupported versions, duplicate or blank IDs, invalid score values, malformed ML/TreeSHAP states, and forbidden ground-truth keys.

Before mapping begins, the exporter also validates the Stage 5 source contract. It rejects legacy records that omit explicit ML availability, prediction, explainability, review, or adaptation fields. Full-schema input paths must be supplied explicitly on the exporter command line.

## Data Boundaries

These artifacts have separate purposes:

- `analyst-alerts.v1.json`: analyst-facing held-out detection records. It contains no per-alert ground truth.
- `evaluator-summary.v1.json`: aggregate evaluation metrics. It is not an analyst-record source.
- `adaptation-demo-scenarios.v1.json`: deterministic demonstrations generated through the real Stage 5 core. They are not formal evaluation results.
- `dashboard-data-manifest.v1.json`: portable paths, hashes, counts, provenance, and publication checks.

Formal evaluation is not demonstration data. Analyst data is not evaluator data.

## Score Semantics

- `modelConfidence`: raw XGBoost softprob confidence. It is not calibrated certainty or threat risk.
- `mlThreatEvidenceScore`: class-aware ML threat evidence used by Stage 4.
- `detectionScore`: immutable automated Signature + ML score produced by Stage 4.
- `operationalPriorityScore`: Stage 5 ranking score after any eligible feedback adjustment and guardrail.
- TreeSHAP values: predicted-class raw-margin attribution. They are not probability changes or risk points.

Legacy `fusionRiskScore` and `currentRiskScore` names exist only in `dashboard/src/utils/dashboardAdapter.ts` while older React components are migrated. They are not canonical contract fields.

## ML States

`recordPresent` distinguishes a missing Stage 3 record from a present record whose prediction is unavailable. An available TreeSHAP explanation must include the predicted class, raw-margin output space, supporting/opposing features, and a passed additivity check. SHAP failure never changes the prediction.

The ML fields are cross-validated: unavailable or missing predictions cannot carry class, confidence, threat-score, or analyst-usable SHAP evidence. When SHAP is available, its explained class and index must match the ML prediction. The evaluator envelope is validated separately before aggregate Reports data is used.

## Feedback Boundary

The loaded ranking comes from Stage 5 `operationalPriorityScore`. Browser feedback uses an explicitly named session-preview layer and does not persist events or rewrite pipeline JSON. Session preview is not persisted historical adaptation and is temporary frontend technical debt.

## Public Data Gate

The analyst exporter scans the generated artifact for forbidden evaluator fields, local filesystem paths, common credential patterns, and duplicate IDs. Schema v1 publishes protocol and port values but no source or destination IP addresses. The GitHub Pages site is an offline research-data prototype, not live monitoring.
