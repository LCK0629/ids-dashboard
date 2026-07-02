# Stage 1 Dataset Preparation

## Dataset

Stage 1 uses CSE-CIC-IDS2018 as the formal dataset source for the IDS dashboard project.

## Folder Structure

- Raw dataset folder: `stage-1/data/raw/cse-cic-ids2018/`
- Detection feature input: `stage-1/data/processed/flow-feature-sample.csv`
- Evaluation labels: `stage-1/data/processed/ground-truth.json`
- Dashboard-ready labelled sample: `stage-1/data/processed/sample-alerts.json`
- Sampling script: `stage-1/scripts/sample_cse_cic_ids2018.py`
- Processed alert schema: `stage-1/alert-schema.md`
- Feature-only schema: `stage-1/schema/flow-feature-schema.md`
- Ground truth schema: `stage-1/schema/ground-truth-schema.md`

## Data Handling Plan

The Stage 1 data preparation flow is:

```txt
CSE-CIC-IDS2018 raw CSV files
-> sample selected benign and attack rows
-> export observable flow features for detection
-> export ground truth labels for evaluation
-> export dashboard-ready labelled alert JSON for UI/reference use
```

The real dataset is not included in this repository. Large raw CSV files should not be committed.

## Alert Schema

The processed dashboard alert JSON format is documented in `stage-1/alert-schema.md`.

The feature-only detection input is documented in `stage-1/schema/flow-feature-schema.md`.

The evaluation-only label file is documented in `stage-1/schema/ground-truth-schema.md`.

Detection engines must use `stage-1/data/processed/flow-feature-sample.csv` and must not use `attackType` or `groundTruth` from `sample-alerts.json` as detection input.

`sample-alerts.json` is kept as a dashboard-ready labelled sample, UI sample, and evaluation reference. It contains derived answer fields and should not be treated as raw detector input.

## Colab Preprocessing Notebook

Stage 1 preprocessing may be prototyped in Google Colab using:

`stage-1/notebooks/cse_cic_ids2018_preprocessing.ipynb`

The notebook is for exploration and preprocessing records. The final reusable logic should remain in:

`stage-1/scripts/sample_cse_cic_ids2018.py`

## Current Prototype Status

The current `prototype-demo/` mock alert data remains unchanged. Stage 1 prepares the future dataset structure only and does not connect the processed JSON to the dashboard yet.
