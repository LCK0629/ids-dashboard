# Stage 1 Ground Truth Schema

This document defines the evaluation-only ground truth file for Stage 1.

The ground truth file is:

```txt
stage-1/data/processed/ground-truth.json
```

## Purpose

`ground-truth.json` maps each sampled flow ID to its true dataset label and mapped dashboard attack category.

Future detection engines must not read this file during prediction. It is only for evaluation, validation, and reporting.

## Schema

```json
{
  "AL-0001": {
    "rawLabel": "FTP-BruteForce",
    "mappedAttackType": "Brute Force",
    "groundTruth": "malicious"
  }
}
```

| Field | Type | Required | Description |
|---|---|---:|---|
| `rawLabel` | string | Yes | Original CSE-CIC-IDS2018 label from the sampled row. |
| `mappedAttackType` | string | Yes | Clean dashboard attack type derived from the raw label. |
| `groundTruth` | string | Yes | `benign` or `malicious`. |

## Notes

- IDs must align with `flow-feature-sample.csv` and `sample-alerts.json`.
- `mappedAttackType` is an answer field and must not be used as detector input.
- `groundTruth` is an answer field and must not be used as detector input.
