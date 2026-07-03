# Stage 4 Fusion Evaluation Summary

Stage 4 combines Stage 2 signature evidence and Stage 3 ML predictions. Ground truth is joined only after fusion for this summary.

- Total fused alerts: 1000
- Stage 3 predictions excluded as out of scope: 0
- Requires analyst review: 456
- Average fusion risk score: 48.57
- Max fusion risk score: 100
- Min fusion risk score: 0
- Signature / ML agreement count: 0
- Signature / ML disagreement count: 15
- ML-only alert count: 505
- Signature-only alert count: 15
- Infiltration ML limitation count: 0

## ID Alignment Summary

Fusion is Stage-2-scoped. ML predictions are used only when IDs match Stage 2 records. Out-of-scope ML predictions are reported for debugging but are not inserted into the dashboard fusion queue.

- Stage 2 record count: 1000
- Stage 3 prediction count: 996
- Matched ID count: 996
- Stage 2 only count: 4
- Stage 3 out-of-scope count: 0
- Overlap rate against Stage 2: 99.60%
- Overlap rate against Stage 3: 100.00%
- Alignment status: OK
- Alignment warning: none

### Stage 2-Only ID Sample

- AL-0376
- AL-0423
- AL-0447
- AL-0984

### Out-of-Scope Stage 3 ID Sample

- none

## Count By Fusion Decision

- LOW_RISK_BENIGN: 476
- ML_ONLY_HIGH_CONFIDENCE: 409
- ML_ONLY_MEDIUM_CONFIDENCE: 96
- SIGNATURE_ONLY_ML_BENIGN: 15
- LOW_RISK_NO_DETECTION_INPUT: 4

## Count By Fusion Confidence Level

- Low: 471
- Critical: 381
- Medium: 105
- High: 43

## Count By Fusion Attack Type

- Benign: 480
- Web Attack: 155
- DoS: 127
- Botnet: 84
- Brute Force: 78
- DDoS: 76

## Notes

- Stage 4 is a prototype fusion evaluation, not final IDS performance.
- Ground truth is joined only after fusion for evaluation.
- Current Stage 3 ML artifacts do not include Infiltration; Stage 4 retains Infiltration signature alerts.
- Fusion scope is defined by Stage 2 signature records (the Stage 1 sample). Stage 3 predictions whose id is outside that scope come from a different Stage 3 test set and are excluded from fusion rather than unioned in.

## Ground Truth Evaluation

- Evaluated alert count: 1000
- Matching fusion attack type count: 792
- Simple fusion accuracy: 0.792
- False positive style count: 109
- False negative style count: 89

## Classification Metrics

- Accuracy: 0.792
- Macro F1: 0.7383
- Weighted F1: 0.7636

### Binary Detection Metrics

- Positive class: malicious
- Negative class: benign
- True positive: 411
- True negative: 391
- False positive: 109
- False negative: 89
- Binary precision: 0.7904
- Binary recall: 0.822
- Binary specificity: 0.782
- Binary F1: 0.8059

### Per-Class Precision / Recall / F1

- Benign: precision 0.8146, recall 0.782, F1 0.798, support 500
- Botnet: precision 1, recall 1, F1 1, support 84
- Brute Force: precision 0.9615, recall 0.8929, F1 0.9259, support 84
- DDoS: precision 1, recall 0.9157, F1 0.956, support 83
- DoS: precision 0.6535, recall 1, F1 0.7904, support 83
- Infiltration: precision 0, recall 0, F1 0, support 83
- Web Attack: precision 0.5355, recall 1, F1 0.6975, support 83

### Confusion Matrix

| True \ Predicted | Benign | Botnet | Brute Force | DDoS | DoS | Infiltration | Web Attack |
|---|---|---|---|---|---|---|---|
| Benign | 391 | 0 | 3 | 0 | 35 | 0 | 71 |
| Botnet | 0 | 84 | 0 | 0 | 0 | 0 | 0 |
| Brute Force | 0 | 0 | 75 | 0 | 9 | 0 | 0 |
| DDoS | 6 | 0 | 0 | 76 | 0 | 0 | 1 |
| DoS | 0 | 0 | 0 | 0 | 83 | 0 | 0 |
| Infiltration | 83 | 0 | 0 | 0 | 0 | 0 | 0 |
| Web Attack | 0 | 0 | 0 | 0 | 0 | 0 | 83 |

## Risk Prioritisation Metrics

- Average fusion risk score for benign records: 19.64
- Average fusion risk score for malicious records: 77.51
- Top-50 precision: 0.98
- Top-100 precision: 0.99
- Top-200 precision: 0.995
- High-risk threshold precision, fusionRiskScore >= 70: 0.8467
- High-risk alert count: 424
- Benign records with high fusionRiskScore: 65
- Malicious records with low fusionRiskScore, fusionRiskScore < 40: 89

## Analyst Review Metrics

- Requires analyst review count: 456
- Review rate: 0.456
- Reviewed malicious count: 369
- Reviewed benign count: 87
- Review precision: 0.8092
- Malicious records not requiring review: 131
- Benign records requiring review: 87

### Count By True Attack Type

- Benign: 500
- Botnet: 84
- Brute Force: 84
- DoS: 83
- DDoS: 83
- Web Attack: 83
- Infiltration: 83

This is a prototype Stage 4 evaluation. It should not be reported as final production IDS accuracy.
