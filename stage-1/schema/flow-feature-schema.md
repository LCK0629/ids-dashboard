# Stage 1 Flow Feature Schema

This document defines the feature-only detection input for future Stage 2 signature detection and Stage 3 ML prediction.

The processed feature file is:

```txt
stage-1/data/processed/flow-feature-sample.csv
```

## Purpose

`flow-feature-sample.csv` contains observable flow-level fields only. Detection engines should use this file as input.

It must not contain answer fields such as:

- `Label`
- `rawLabel`
- `attackType`
- `mappedAttackType`
- `groundTruth`
- `severity`
- `similarityKey`

## Schema

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Shared alert/flow ID used to join with evaluation labels. |
| `timestamp` | string | Yes | Flow timestamp from the sampled record. |
| `sourceIp` | string | Yes | Source IP address, or `unknown-source` when unavailable in the source CSV. |
| `destinationIp` | string | Yes | Destination IP address, or `unknown-destination` when unavailable in the source CSV. |
| `destinationPort` | number | Yes | Destination port. |
| `protocol` | string | Yes | Network protocol, for example `TCP`, `UDP`, or `ICMP`. |
| `flowDuration` | number | Yes | Flow duration. |
| `totalFwdPackets` | number | Yes | Total forward packets. |
| `totalBwdPackets` | number | Yes | Total backward packets. |
| `flowBytesPerSecond` | number | Yes | Flow bytes per second. |
| `flowPacketsPerSecond` | number | Yes | Flow packets per second. |
| `packetLengthMean` | number | Yes | Mean packet length. |
| `fwdPacketLengthMean` | number | Yes | Mean forward packet length. |
| `synFlagCount` | number | Yes | SYN flag count. |
| `ackFlagCount` | number | Yes | ACK flag count. |
| `finFlagCount` | number | Yes | FIN flag count. |
| `rstFlagCount` | number | Yes | RST flag count. |

## Notes

- This file is the correct Stage 1 input for detection engines.
- Detection engines must not read `sample-alerts.json` as prediction input because that file contains derived labels.
- Some CSE-CIC-IDS2018 CSV files used in Stage 1 do not include source or destination IP columns, so `unknown-source` and `unknown-destination` are preserved where needed.
