# Stage 2 Flow-Based Signature Detection

## Purpose

Stage 2 adds a standalone flow-based signature detection engine for the Hybrid Human-in-the-Loop IDS Dashboard.

It reads the Stage 1 feature-only CSV, applies lightweight signature rules, and writes signed flow objects that can later be used by the fusion engine.

## What Signature-Based Detection Means

Signature-based detection identifies known attack patterns using predefined rules. In this project, signatures are represented as simple conditions over flow-level fields such as `protocol`, `port`, and `flowFeatures`.

Example:

```txt
protocol = TCP
destinationPort = 22
flowPacketsPerSecond >= 10
totalFwdPackets >= 10
flowDuration <= 5000000
```

This represents an SSH brute-force flow pattern.

`attackType` and `groundTruth` are not used as signature detection inputs. A real flow does not directly tell the detection engine its attack category.

The demo script reads:

- `stage-1/data/processed/flow-feature-sample.csv` for prediction input.
- `stage-1/data/processed/ground-truth.json` only after prediction, for evaluation summaries.

## Why Flow-Based Signatures Are Used

This project uses CSE-CIC-IDS2018 flow-level records, not raw packet payloads. Because of that, Stage 2 does not implement full Snort or Suricata packet inspection.

Instead, it uses lightweight flow-based rules inspired by signature-based IDS concepts. This keeps the detection layer aligned with the dataset and makes the results easier to explain in the dashboard.

## How To Run

From the repository root:

```powershell
node stage-2/scripts/run-signature-demo.js
```

The script will:

1. Load `stage-1/data/processed/flow-feature-sample.csv`.
2. Load `stage-2/rules/flow-signatures.json`.
3. Apply the flow-based signature rules.
4. Load `stage-1/data/processed/ground-truth.json` for evaluation only.
5. Write signed alerts to `stage-2/data/signature-output.sample.json`.
6. Write post-prediction evaluation summaries to `stage-2/evaluation/`.
7. Print a summary of signature hits.

## Output

Each signed alert preserves the original Stage 1 alert fields and adds:

```json
{
  "signatureHit": true,
  "signatureId": "SIG-SSH-BRUTE-FORCE",
  "signatureName": "SSH Brute Force Flow Pattern",
  "signatureAttackType": "Brute Force",
  "signatureSeverity": "Medium",
  "signatureEvidence": "Matched SSH Brute Force Flow Pattern using protocol=TCP, destinationPort=22, flowPacketsPerSecond {\"min\":10}, totalFwdPackets {\"min\":10}, flowDuration {\"max\":5000000}."
}
```

Rule metadata uses `predictedAttackType` to describe the attack type predicted by the rule. This metadata is copied into signed output as `signatureAttackType`. It is not used as a matching condition.

If no rule matches, the alert receives:

```json
{
  "signatureHit": false,
  "signatureId": null,
  "signatureName": null,
  "signatureAttackType": null,
  "signatureSeverity": null,
  "signatureEvidence": "No flow-based signature matched."
}
```

## Evaluation Outputs

The demo also writes:

```txt
stage-2/evaluation/signature-evaluation-summary.json
stage-2/evaluation/signature-evaluation-summary.md
```

These files record post-prediction evaluation metrics. They are generated only after the feature-only prediction step and after ground truth is joined for evaluation.

The evaluation summary includes precision, recall, F1 score, benign signature hits, hits by signature, hits by predicted attack type, and coverage by true attack type.

## Role In The Later Fusion Engine

Stage 2 prepares one detection signal for the later fusion engine. Future stages will combine:

- Signature-based result from Stage 2.
- XGBoost ML prediction from Stage 3.
- Human feedback and Exception Memory from Stage 5.

The fusion engine will use these signals to calculate final alert priority.

## Not Included Yet

- Full Snort or Suricata packet inspection.
- Raw packet payload analysis.
- XGBoost model training.
- Fusion scoring.
- Human feedback integration.
- Dashboard integration.
