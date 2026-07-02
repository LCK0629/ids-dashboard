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

## Notes

- `baseRiskScore` should not change after initial conversion.
- `currentRiskScore` can change after analyst feedback.
- `groundTruth` is for evaluation, not normal dashboard decision-making.
- `similarityKey` is used for adaptive scoring across similar alerts.

