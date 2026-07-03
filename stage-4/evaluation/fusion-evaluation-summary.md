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

### Count By True Attack Type

- Benign: 500
- Botnet: 84
- Brute Force: 84
- DoS: 83
- DDoS: 83
- Web Attack: 83
- Infiltration: 83

This is a prototype Stage 4 evaluation. It should not be reported as final production IDS accuracy.
