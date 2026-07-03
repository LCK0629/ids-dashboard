# Stage 2 Signature Evaluation Summary

## Overall Metrics

- Total records: 1000
- Signature hits: 15
- No signature hits: 985
- True positives: 8
- False positives: 7
- False negatives: 492
- True negatives: 493
- Precision: 0.5333 (53.33%)
- Recall: 0.0160 (1.60%)
- F1 score: 0.0311 (3.11%)
- Benign records with signature hit: 7

## Hits By Signature

- SIG-WEB-ATTACK-FLOW: 4
- SIG-SSH-BRUTE-FORCE: 11

## Hits By Predicted Attack Type

- Web Attack: 4
- Brute Force: 11

## Coverage By True Attack Type

- Benign: 7/500 (1.40%)
- Brute Force: 8/84 (9.52%)
- Botnet: 0/84 (0.00%)
- DoS: 0/83 (0.00%)
- DDoS: 0/83 (0.00%)
- Web Attack: 0/83 (0.00%)
- Infiltration: 0/83 (0.00%)

## Notes

- Prediction uses flow-feature-sample.csv only.
- ground-truth.json is joined only after prediction for evaluation.
- Rules are prototype flow-level heuristics, not full packet-payload Snort rules.
