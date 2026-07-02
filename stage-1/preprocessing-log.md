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

## Required Follow-up - Full Attack-Type Sampling

The previous generated sample was valid, but it did not cover all desired attack categories. It contained:

- `Benign`: 266
- `Unknown Attack`: 500

The root cause is that the notebook was loading a limited CSV selection, so only a narrow set of raw attack labels was available during sampling.

Notebook update:

- Updated the notebook to use all available CSV files instead of only `02-16-2018.csv`.
- Added cross-file raw `Label` distribution auditing.
- Added mapped `attackType` distribution auditing.
- Improved raw label mapping for target attack types:
  - `Benign`
  - `Brute Force`
  - `Heartbleed`
  - `Botnet`
  - `DoS`
  - `DDoS`
  - `Web Attack`
  - `Infiltration`
- Changed sampling to group by mapped `attackType`, not only benign vs malicious.
- Added target and collected sample count reporting for each mapped attack type.
- Fixed repeated CSV header rows appearing inside sampled data, such as `Dst Port` appearing as a field value.
- Added safer numeric port conversion so invalid port values fall back to `0` instead of stopping alert conversion.

Next run should regenerate `stage-1/data/processed/sample-alerts.json` using the improved notebook and verify that the output includes the available target attack types.

## Required Follow-up - Final Unknown Attack Mapping

A later full-sample run produced 1000 valid alerts with 500 benign and 500 malicious records. The remaining `Unknown Attack` group was caused by raw web attack labels that should be mapped into the dashboard `Web Attack` category:

- `Brute Force -XSS` -> `Web Attack`
- `SQL Injection` -> `Web Attack`
- `Brute Force -Web` -> `Web Attack`

Notebook update:

- Strengthened label normalization for hyphenated and spaced labels.
- Added explicit mapping for `Brute Force -Web` to `Web Attack`.
- Kept `Brute Force -XSS` and `SQL Injection` mapped to `Web Attack`.
- Removed `Unknown Attack` from the target attack-type sampling list so future generated samples focus on known dashboard attack categories.

Repository sample repair:

- Updated the existing repository `stage-1/data/processed/sample-alerts.json` to remap the previous old `Unknown Attack` records with raw labels `DoS attacks-Hulk` and `DoS attacks-SlowHTTPTest` into `DoS`.
- The previous repository sample had no `Unknown Attack` records after repair, but it still reflected the earlier 766-alert sample. It has now been replaced by the final 1000-alert sample generated with the final mapping rules.

## Run Record - Final 1000 Alert Sample

- Generated file reviewed: `C:\Users\cheek\Downloads\sample-alerts (2).json`
- Repository output path: `stage-1/data/processed/sample-alerts.json`
- Number of processed alert objects: 1000
- Benign sample size: 500
- Attack sample size: 500
- Ground truth distribution after sampling:
  - `benign`: 500
  - `malicious`: 500
- Attack type distribution after conversion:
  - `Benign`: 500
  - `Brute Force`: 84
  - `Botnet`: 84
  - `DoS`: 83
  - `DDoS`: 83
  - `Web Attack`: 83
  - `Infiltration`: 83
  - `Unknown Attack`: 0
- Severity distribution after conversion:
  - `Low`: 500
  - `Medium`: 84
  - `High`: 333
  - `Critical`: 83
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
  - no alert uses `Unknown Attack`

## Follow-up - Flow Features Added For Stage 2

- Added `flowFeatures` to the processed alert schema and current `stage-1/data/processed/sample-alerts.json`.
- Updated the preprocessing notebook so future exports preserve selected CSE-CIC-IDS2018 flow columns inside `flowFeatures`.
- Clarified that `attackType` and `groundTruth` are label-derived evaluation fields, not Stage 2 detection inputs.
- Stage 2 signature rules now use `protocol`, `port`, and `flowFeatures` instead of checking `attackType`.

## Follow-up - Detection Features Separated From Labels

- Created `stage-1/data/processed/flow-feature-sample.csv` as the feature-only detection input.
- Created `stage-1/data/processed/ground-truth.json` as the evaluation-only answer file.
- Retained `stage-1/data/processed/sample-alerts.json` as a dashboard-ready labelled sample, UI sample, and evaluation reference.
- Updated the preprocessing notebook to export all three files from the same sampled rows so IDs align.
- Confirmed answer fields are separated from detection input:
  - `flow-feature-sample.csv` does not contain `Label`, `rawLabel`, `attackType`, `mappedAttackType`, `groundTruth`, `severity`, or `similarityKey`.
  - `ground-truth.json` should not be read by detection engines during prediction.

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
