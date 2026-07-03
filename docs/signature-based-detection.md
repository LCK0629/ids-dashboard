# Signature-Based Detection Design

## 1. Purpose

Stage 2 implements a lightweight flow-based signature detection layer for the Hybrid Human-in-the-Loop IDS Dashboard.

This layer is one detection signal. It will later be combined with:

- Stage 3 XGBoost ML prediction
- Stage 5 human feedback / Exception Memory
- Stage 4 Fusion Engine

The goal is to provide interpretable rule-based evidence before later stages combine signature results, ML scores, and analyst feedback into final alert priority.

## 2. What Signature-Based Detection Means

Signature-based detection identifies known attack patterns using predefined rules.

In this project, a signature rule is a condition over observable flow-level fields.

Example:

```txt
protocol = TCP
destinationPort = 22
flowPacketsPerSecond >= 10
totalFwdPackets >= 10
flowDuration <= 5000000
```

This represents an SSH brute-force-like flow pattern.

## 3. Why This Project Uses Flow-Based Signatures

This project uses CSE-CIC-IDS2018 flow-level records. Therefore, Stage 2 does not implement full Snort or Suricata packet inspection.

Snort / Suricata inspect raw packets, payloads, and protocol-level signatures. This project currently uses CIC-style flow features, so rules operate on flow-level fields.

The Stage 2 rules are Snort-inspired flow-level heuristics, not full packet-payload signatures.

## 4. Allowed Rule Input Fields

Stage 2 rules may use observable features from:

```txt
stage-1/data/processed/flow-feature-sample.csv
```

Allowed rule input fields:

- `protocol`
- `destinationPort`
- `flowDuration`
- `totalFwdPackets`
- `totalBwdPackets`
- `flowBytesPerSecond`
- `flowPacketsPerSecond`
- `packetLengthMean`
- `fwdPacketLengthMean`
- `synFlagCount`
- `ackFlagCount`
- `finFlagCount`
- `rstFlagCount`

These fields represent network flow behavior and are suitable as detector input.

## 5. Forbidden Rule Input Fields

Rules must not use answer-derived fields as matching input.

Forbidden fields:

- `Label`
- `rawLabel`
- `attackType`
- `mappedAttackType`
- `groundTruth`
- `severity`
- `similarityKey`

Using these fields would create label leakage because they are derived from the dataset answers.

Detection engines must use feature-only input. Ground truth labels are joined only after prediction for evaluation.

## 6. Current Implemented Rules

Each rule uses `predictedAttackType` as output metadata. It is not a matching condition. Each rule also includes:

- `validationStatus`: currently `prototype-heuristic`
- `rationale`: short reasons explaining why the observable flow conditions may indicate the predicted attack type

### `SIG-FTP-BRUTE-FORCE`

- Predicted attack type: `Brute Force`
- Main observable conditions:
  - `protocol = TCP`
  - `destinationPort = 21`
  - `flowPacketsPerSecond >= 10`
  - `totalFwdPackets >= 10`
  - `flowDuration <= 5000000`
- Rationale: FTP brute-force attempts often create repeated short TCP flows against FTP port 21.
- Limitation: The rule cannot inspect login payloads or confirm authentication failure messages.

### `SIG-SSH-BRUTE-FORCE`

- Predicted attack type: `Brute Force`
- Main observable conditions:
  - `protocol = TCP`
  - `destinationPort = 22`
  - `flowPacketsPerSecond >= 10`
  - `totalFwdPackets >= 10`
  - `flowDuration <= 5000000`
- Rationale: SSH brute-force attempts often create repeated short TCP flows against SSH port 22.
- Limitation: The rule cannot inspect SSH authentication results or distinguish all automated login tools from unusual but legitimate activity.

### `SIG-DOS-HIGH-RATE-FLOW`

- Predicted attack type: `DoS`
- Main observable conditions:
  - `protocol = TCP`
  - `flowPacketsPerSecond >= 650`
  - `flowPacketsPerSecond <= 899`
  - `totalFwdPackets >= 80`
  - `totalBwdPackets <= 10`
- Rationale: DoS-like flows may show high packet rate, high forward packet count, and limited backward response.
- Limitation: High-rate legitimate traffic may also match this pattern, and some DoS attacks may fall outside the selected thresholds.

### `SIG-DDOS-HIGH-RATE-FLOW`

- Predicted attack type: `DDoS`
- Main observable conditions:
  - `protocol = TCP`
  - `flowPacketsPerSecond >= 900`
  - `totalFwdPackets >= 120`
  - `totalBwdPackets <= 8`
- Rationale: DDoS-like flows may produce very high packet rates and strong forward traffic imbalance.
- Limitation: True distributed behavior is difficult to prove from a single flow row without broader source-distribution context.

### `SIG-BOTNET-BEACON-FLOW`

- Predicted attack type: `Botnet`
- Main observable conditions:
  - `flowDuration >= 10000000`
  - `flowPacketsPerSecond >= 20`
  - `flowPacketsPerSecond <= 120`
  - `totalFwdPackets >= 20`
  - `totalBwdPackets <= 15`
- Rationale: Botnet-like communication may appear as longer-lived, repeated, moderate-rate beacon-style flows.
- Limitation: More reliable botnet detection usually needs host history, command-and-control indicators, or destination reputation.

### `SIG-WEB-ATTACK-FLOW`

- Predicted attack type: `Web Attack`
- Main observable conditions:
  - `protocol = TCP`
  - `destinationPort` is `80` or `443`
  - `packetLengthMean >= 300`
  - `fwdPacketLengthMean >= 250`
  - `flowDuration <= 5000000`
- Rationale: Web attack attempts may appear as short web flows with larger request or packet payload sizes.
- Limitation: Flow-level fields cannot inspect HTTP payloads, URLs, SQL strings, XSS payloads, or request parameters.

### `SIG-INFILTRATION-LONG-FLOW`

- Predicted attack type: `Infiltration`
- Main observable conditions:
  - `flowDuration >= 20000000`
  - `totalBwdPackets >= 20`
  - `flowBytesPerSecond >= 10000`
- Rationale: Infiltration-like activity may involve long-running flows with sustained data transfer and notable reverse traffic.
- Limitation: Infiltration is context-dependent and is difficult to detect reliably using flow-level features alone.

## 7. Heuristic Thresholds

Thresholds such as:

- `flowPacketsPerSecond >= 900`
- `flowDuration <= 5000000`
- `totalFwdPackets >= 120`

are prototype heuristic thresholds.

They are not final validated thresholds.

These thresholds should later be calibrated using feature distribution analysis and evaluation against ground truth after prediction.

## 8. Stage 2 Evaluation Process

The correct Stage 2 evaluation flow is:

1. `flow-feature-sample.csv`
2. Apply signature rules
3. Produce `signature-output.sample.json`
4. Join `ground-truth.json` only after prediction
5. Calculate hits, false positives, false negatives, and benign hits

`ground-truth.json` is not used during rule matching.

The demo script writes formal evaluation summaries to:

```txt
stage-2/evaluation/signature-evaluation-summary.json
stage-2/evaluation/signature-evaluation-summary.md
```

These files are generated after prediction and after ground truth is joined for evaluation.

## 9. Limitations

- Flow-level signatures cannot inspect packet payloads.
- The rules are simplified heuristics.
- Some attacks may not have clear flow-level patterns.
- Thresholds may cause false positives or false negatives.
- Infiltration and Web Attack rules are weaker because they require richer contextual or payload features.
- Current Stage 2 is not a replacement for Snort, Suricata, or a production IDS.

## 10. Role in Final Hybrid IDS

Stage 2 will later provide:

- `signatureHit`
- `signatureId`
- `signatureAttackType`
- `signatureSeverity`
- `signatureEvidence`

These fields will be combined with ML output:

- `predictedAttackType`
- `modelConfidence`
- `baseRiskScore`

and human feedback:

- `exceptionFalsePositive`
- `analystFeedback`
- `feedbackConfidence`

inside the future Fusion Engine.

## 11. Suggested Report Wording

Stage 2 implements a lightweight flow-based signature detection layer. Instead of using ground-truth labels as input, it applies predefined rules over observable CIC-style flow features such as protocol, destination port, packet rate, flow duration, and packet counts. These rules are intended as Snort-inspired flow-level heuristics rather than full packet-payload signatures. The output provides interpretable signature evidence that can later be fused with machine learning predictions and human feedback.
