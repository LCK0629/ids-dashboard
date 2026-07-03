# Stage 3 XGBoost ML Detection

## Purpose

Stage 3 prepares an XGBoost-based machine-learning IDS classifier for the Hybrid Human-in-the-Loop IDS Dashboard.

The future model will classify CSE-CIC-IDS2018 flow records into dashboard attack types using observable flow-level features.

Stage 3A scaffold exists in this folder. Stage 3B training should be performed in Google Colab using `stage-3/notebooks/xgboost_ids_training.ipynb`.

## Stage 3 Role in the Hybrid IDS

Stage 3 provides the machine-learning detection signal.

Later Stage 4 will combine:

- Stage 2 signature evidence.
- Stage 3 ML prediction.
- Stage 5 human feedback and Exception Memory.

## Input Data

Training will use CSE-CIC-IDS2018 flow features and supervised labels.

For Colab training, use either:

- An uploaded `/content/archive.zip`.
- A Google Drive archive such as `/content/drive/MyDrive/cse-cic-ids2018/archive.zip`.

Raw CSE-CIC-IDS2018 CSV files and dataset archives should not be committed to GitHub.

For local demo prediction, the intended feature-only input is:

```txt
stage-1/data/processed/flow-feature-sample.csv
```

Ground truth for evaluation is:

```txt
stage-1/data/processed/ground-truth.json
```

## Training Principle

Training may use both observable flow features and labels because supervised learning requires labelled examples.

Training should not use dashboard-derived or answer-derived fields such as:

```txt
Label
rawLabel
attackType
mappedAttackType
groundTruth
severity
similarityKey
```

Training should use only observable numeric or encoded categorical flow features.

## Prediction Principle

Prediction must use feature-only records.

The prediction step must not read ground truth, raw labels, mapped attack types, severity, or similarity keys. Ground truth should be joined only after prediction for evaluation.

After Colab training, only model artifacts and small output/evaluation files should be copied back into the repository.

## Expected Model Artifacts

Future training should write:

```txt
stage-3/models/xgboost_ids_model.json
stage-3/models/feature-columns.json
stage-3/models/label-mapping.json
stage-3/models/preprocessing-config.json
```

- `xgboost_ids_model.json`: trained XGBoost model.
- `feature-columns.json`: ordered feature list used during training and prediction.
- `label-mapping.json`: mapping between encoded model labels and dashboard attack types.
- `preprocessing-config.json`: preprocessing choices such as categorical encoding, scaling decisions, and forbidden fields.

## Expected ML Output Format

Future prediction output should be written to:

```txt
stage-3/outputs/ml-predictions.sample.json
```

Each prediction should eventually include:

```json
{
  "id": "AL-0001",
  "predictedAttackType": "DoS",
  "modelConfidence": 0.91,
  "baseRiskScore": 91
}
```

`modelConfidence` is the classifier probability for the selected class. `baseRiskScore` can initially be derived from confidence, for example confidence multiplied by 100, but this can be refined in Stage 4.

## Evaluation Plan

Future evaluation should join predictions with `stage-1/data/processed/ground-truth.json` only after prediction.

Evaluation metrics should include:

- Accuracy.
- Precision.
- Recall.
- F1 score.
- Confusion matrix.
- Per-class performance.
- False positive count.
- False negative count.

Evaluation outputs should be stored under:

```txt
stage-3/evaluation/
```

## What Is Not Included Yet

- No final model is trained in this scaffold task.
- No dashboard integration.
- No Fusion Engine.
- No human feedback adaptation.
- No production IDS deployment.
- No Snort or Suricata integration.

## How to Run Later

For Stage 3B training, open this notebook in Google Colab:

```txt
stage-3/notebooks/xgboost_ids_training.ipynb
```

The Python scripts remain scaffold commands for later local implementation:

```powershell
python stage-3/scripts/train_xgboost_ids.py
python stage-3/scripts/run_ml_prediction_demo.py
```

The Colab notebook exports artifacts that can later be copied into:

```txt
stage-3/models/
stage-3/outputs/
stage-3/evaluation/
```
