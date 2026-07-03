# Stage 4 Fusion Evaluation Summary

Stage 4 combines Stage 2 signature evidence and Stage 3 ML predictions. Ground truth is joined only after fusion for this summary.

- Total fused alerts: 3186
- Requires analyst review: 2399
- Average fusion risk score: 76.57
- Max fusion risk score: 100
- Min fusion risk score: 0
- Signature / ML agreement count: 0
- Signature / ML disagreement count: 0
- ML-only alert count: 2186
- Signature-only alert count: 500

## Count By Fusion Decision

- ML_ONLY_NO_SIGNATURE_RECORD: 2186
- LOW_RISK_NO_DETECTION_INPUT: 500
- SIGNATURE_ONLY_NO_ML: 417
- SIGNATURE_ONLY_ML_LIMITATION: 83

## Count By Fusion Confidence Level

- Critical: 1820
- Low: 500
- High: 495
- Medium: 371

## Count By Fusion Attack Type

- Benign: 890
- Brute Force: 553
- Botnet: 484
- DDoS: 484
- DoS: 415
- Web Attack: 277
- Infiltration: 83

## Notes

- Stage 4 is a prototype fusion evaluation, not final IDS performance.
- Ground truth is joined only after fusion for evaluation.
- Current Stage 3 ML artifacts do not include Infiltration; Stage 4 retains Infiltration signature alerts.

## Ground Truth Evaluation

- Evaluated alert count: 1000
- Matching fusion attack type count: 1000
- Simple fusion accuracy: 1
- False positive style count: 0
- False negative style count: 0

### Count By True Attack Type

- Benign: 500
- Botnet: 84
- Brute Force: 84
- Infiltration: 83
- DoS: 83
- DDoS: 83
- Web Attack: 83

This is a prototype Stage 4 evaluation. It should not be reported as final production IDS accuracy.
