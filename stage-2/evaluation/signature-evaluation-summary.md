# Stage 2 Signature Evaluation Summary

## Overall Metrics

- Total records: 1000
- Signature hits: 500
- No signature hits: 500
- True positives: 500
- False positives: 0
- False negatives: 0
- True negatives: 500
- Precision: 1.0000 (100.00%)
- Recall: 1.0000 (100.00%)
- F1 score: 1.0000 (100.00%)
- Benign records with signature hit: 0

## Hits By Signature

- SIG-FTP-BRUTE-FORCE: 76
- SIG-SSH-BRUTE-FORCE: 8
- SIG-BOTNET-BEACON-FLOW: 84
- SIG-DOS-HIGH-RATE-FLOW: 83
- SIG-DDOS-HIGH-RATE-FLOW: 83
- SIG-WEB-ATTACK-FLOW: 83
- SIG-INFILTRATION-LONG-FLOW: 83

## Hits By Predicted Attack Type

- Brute Force: 84
- Botnet: 84
- DoS: 83
- DDoS: 83
- Web Attack: 83
- Infiltration: 83

## Coverage By True Attack Type

- Benign: 0/500 (0.00%)
- Brute Force: 84/84 (100.00%)
- Botnet: 84/84 (100.00%)
- DoS: 83/83 (100.00%)
- DDoS: 83/83 (100.00%)
- Web Attack: 83/83 (100.00%)
- Infiltration: 83/83 (100.00%)

## Notes

- Prediction uses flow-feature-sample.csv only.
- ground-truth.json is joined only after prediction for evaluation.
- Rules are prototype flow-level heuristics, not full packet-payload Snort rules.
