# Stage 3 ML Evaluation Summary

- Accuracy: 0.9309
- Test records: 2186

## Classification Report

```txt
              precision    recall  f1-score   support

      Benign       0.99      0.96      0.98       400
      Botnet       1.00      1.00      1.00       400
 Brute Force       0.78      0.92      0.85       400
        DDoS       1.00      1.00      1.00       400
         DoS       0.90      0.75      0.82       400
  Web Attack       0.94      0.98      0.96       186

    accuracy                           0.93      2186
   macro avg       0.94      0.94      0.93      2186
weighted avg       0.93      0.93      0.93      2186

```

## False Positive Notes
- Benign: 4
- Botnet: 0
- Brute Force: 101
- DDoS: 1
- DoS: 33
- Web Attack: 12

## False Negative Notes
- Benign: 14
- Botnet: 0
- Brute Force: 32
- DDoS: 0
- DoS: 101
- Web Attack: 4

## Current Limitation

The imported Stage 3 model artifacts do not include `Infiltration` in `stage-3/models/label-mapping.json`. A follow-up training run should verify whether `Infilteration` / `Infiltration` appears in the selected raw training source and retrain with that class included where available.

## Known Limitation

The current evaluation does not include `Infiltration`. Metrics are reported only for the six classes present in the trained model. This should be considered when comparing Stage 2 and Stage 3.

Stage 2 includes an Infiltration signature rule, but Stage 3 currently does not include an Infiltration ML class.

> The reported Stage 3 ML metrics exclude Infiltration because the current trained model artifacts do not include that class. The model should not be described as a full seven-class classifier until retrained with Infiltration included.
