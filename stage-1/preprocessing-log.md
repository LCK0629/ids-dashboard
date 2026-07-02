# Stage 1 Preprocessing Log

## Dataset

CSE-CIC-IDS2018

## Tool

Google Colab / Jupyter Notebook

## Purpose

Explore the dataset, inspect labels, clean invalid values, sample rows, and convert labelled flow records into dashboard-style IDS alerts.

## Planned Processing Steps

1. Load raw CSV files.
2. Inspect columns and label distribution.
3. Clean missing, NaN, and infinite values.
4. Sample benign and attack records.
5. Map dataset labels to `groundTruth`, `attackType`, `severity`, and `riskScore`.
6. Convert sampled rows into alert objects based on `stage-1/alert-schema.md`.
7. Export processed alerts to `stage-1/data/processed/sample-alerts.json`.

## Recording Rules

- Record dataset files used.
- Record sample size.
- Record benign / malicious ratio.
- Record label distribution before and after sampling.
- Record cleaning decisions.
- Record any columns dropped or renamed.
- Record output file path.

## Required Run Record

For each preprocessing run, record:

- Dataset file used
- Number of rows loaded
- Number of rows after cleaning
- Missing / invalid values removed
- Label distribution before sampling
- Label distribution after sampling
- Benign sample size
- Attack sample size
- Output JSON path
- Any limitations, such as missing source/destination IP columns

## Current Status

Stage 1 sample alert JSON has been generated, validated, and copied into `stage-1/data/processed/sample-alerts.json`. The processed JSON has not been connected to the dashboard yet.

## Run Record - Sample Alerts Generated

- Dataset file used: CSE-CIC-IDS2018 source accessed through the Stage 1 preprocessing notebook / KaggleHub workflow.
- Generated file reviewed: `C:\Users\cheek\Downloads\sample-alerts.json`
- Repository output path: `stage-1/data/processed/sample-alerts.json`
- Number of processed alert objects: 766
- Benign sample size: 266
- Attack sample size: 500
- Ground truth distribution after sampling:
  - `benign`: 266
  - `malicious`: 500
- Severity distribution after conversion:
  - `Low`: 266
  - `Medium`: 500
- Attack type distribution after conversion:
  - `Benign`: 266
  - `Unknown Attack`: 500
- Schema validation result: passed
- Validation checks completed:
  - required fields exist
  - alert IDs are unique
  - severity values are valid
  - `groundTruth` values are valid
  - status is `Unreviewed`
  - confidence and risk scores are within 0-100
  - port is numeric
  - `similarityKey` is not empty
- Limitation noted: malicious records currently map to `Unknown Attack`, so future preprocessing should inspect raw `Label` values and improve label-to-attack-type mapping if needed.

## Archive Inspection Notes

Local file inspected:

```txt
C:\Users\cheek\Downloads\archive.zip
```

Findings:

- The archive contains 10 CSV files named by date.
- All inspected CSV files include `Label` as the final column.
- Most files have 80 columns starting with `Dst Port`, `Protocol`, and `Timestamp`.
- `02-20-2018.csv` has 84 columns and includes `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`.
- Most other inspected files do not include source or destination IP columns, so Stage 1 conversion must use safe fallback values when those fields are unavailable.

Notebook update:

- Updated `stage-1/notebooks/cse_cic_ids2018_preprocessing.ipynb` to read from `archive.zip` directly.
- Added schema inspection for mixed CSV column layouts.
- Added safe field access for optional `Src IP` and `Dst IP` columns.
