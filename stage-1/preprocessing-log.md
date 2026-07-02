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

## Current Status

Notebook template prepared. Real dataset preprocessing has not been run yet.

