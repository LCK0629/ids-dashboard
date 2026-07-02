# Stage 1 Processed Alert Schema

This document defines the processed dashboard alert format for Stage 1 CSE-CIC-IDS2018 integration.

The processed output file is:

```txt
stage-1/data/processed/sample-alerts.json
```

## Schema

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Unique alert ID, for example `AL-0001`. |
| `timestamp` | string | Yes | Alert time from the dataset or generated during conversion. |
| `sourceIp` | string | Yes | Source IP address. |
| `destinationIp` | string | Yes | Destination IP address. |
| `protocol` | string | Yes | Network protocol, for example `TCP`, `UDP`, or `ICMP`. |
| `port` | number | Yes | Destination port. |
| `attackType` | string | Yes | Attack category or `Benign`. |
| `severity` | string | Yes | `Critical`, `High`, `Medium`, or `Low`. |
| `confidence` | number | Yes | Estimated confidence score from 0 to 100. |
| `baseRiskScore` | number | Yes | Original risk score before feedback. |
| `currentRiskScore` | number | Yes | Risk score after possible feedback adjustment. |
| `status` | string | Yes | Initial value should be `Unreviewed`. |
| `groundTruth` | string | Yes | `malicious` or `benign`. Used for evaluation. |
| `similarityKey` | string | Yes | Key used to group similar alerts. |
| `triggerReason` | string | Yes | Short explanation of why the alert was generated. |
| `evidence` | string | Yes | Evidence based on sampled flow and dataset label. |
| `recommendedAction` | string | Yes | Suggested analyst action. |
| `flowFeatures` | object | Yes | Flow-level numeric features used by Stage 2 signature detection and future Stage 3 ML detection. |

## `flowFeatures` Object

| Field | Type | Required | Description |
|---|---|---:|---|
| `flowDuration` | number | Yes | Flow duration from the CSE-CIC-IDS2018 flow record. |
| `totalFwdPackets` | number | Yes | Total forward packets. |
| `totalBackwardPackets` | number | Yes | Total backward packets. |
| `flowBytesPerSecond` | number | Yes | Flow bytes per second. |
| `flowPacketsPerSecond` | number | Yes | Flow packets per second. |
| `synFlagCount` | number | Yes | SYN flag count. |
| `ackFlagCount` | number | Yes | ACK flag count. |
| `rstFlagCount` | number | Yes | RST flag count. |
| `fwdPacketLengthMean` | number | Yes | Mean forward packet length. |
| `packetLengthMean` | number | Yes | Mean packet length. |

## Notes

- `baseRiskScore` should not change after initial conversion.
- `currentRiskScore` can change after analyst feedback.
- `groundTruth` is for evaluation, not normal dashboard decision-making.
- `attackType` is derived from dataset labels and is for evaluation and dashboard explanation. It should not be used as a Stage 2 detection condition.
- `flowFeatures` should come from CSE-CIC-IDS2018 flow columns and can be used as detection input.
- `similarityKey` is used for adaptive scoring across similar alerts.
