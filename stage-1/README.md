# Stage 1 Dataset Preparation

## Dataset

Stage 1 uses CSE-CIC-IDS2018 as the formal dataset source for the IDS dashboard project.

## Folder Structure

- Raw dataset folder: `stage-1/data/raw/cse-cic-ids2018/`
- Processed output: `stage-1/data/processed/sample-alerts.json`
- Sampling script: `stage-1/scripts/sample_cse_cic_ids2018.py`
- Processed alert schema: `stage-1/alert-schema.md`

## Data Handling Plan

The Stage 1 data preparation flow is:

```txt
CSE-CIC-IDS2018 raw CSV files
-> sample selected benign and attack rows
-> convert sampled flow records into dashboard alert JSON
-> use converted alerts in a later dashboard integration step
```

The real dataset is not included in this repository. Large raw CSV files should not be committed.

## Alert Schema

The processed dashboard alert JSON format is documented in `stage-1/alert-schema.md`.

## Current Prototype Status

The current `prototype-demo/` mock alert data remains unchanged. Stage 1 prepares the future dataset structure only and does not connect the processed JSON to the dashboard yet.
