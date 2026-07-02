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
6. Print a summary of signature hits.

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
