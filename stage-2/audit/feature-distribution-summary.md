# Stage 2B Feature Distribution Summary

Stage 2B is an audit, not a new detector. Ground truth is used only for analysis and reporting. Rules still run on feature-only input during detection.

The audit supports rule interpretation, but it does not prove production readiness or globally optimal thresholds. Held-out validation is still required before making stronger claims.

## Key Observations

- Packet-rate and packet-count features are most relevant to DoS and DDoS rule families.
- Destination port separates service-specific brute-force and web-flow rule families in the current sample.
- Duration and byte-rate features are most relevant to Botnet and Infiltration-like rule families.
- Some web and infiltration behavior can overlap with benign traffic in real deployments because payload and host context are unavailable.

## Benign

- Total records: 500
- Top destination ports: 0 (129), 80 (90), 53 (51), 443 (35), 3389 (23), 445 (16), 9984 (13), 67 (12), 22 (11), 23 (3)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 0.00 | 4261.50 | 476750.00 | 112639830.00 | 112641148.30 | 112641293.55 | 118788383.00 | 34340110.65 |
| `totalFwdPackets` | 1.00 | 1.00 | 3.00 | 5.00 | 11.00 | 21.05 | 1041.00 | 12.14 |
| `totalBwdPackets` | 0.00 | 0.00 | 1.00 | 3.25 | 11.00 | 21.00 | 2688.00 | 23.38 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 0.00 | 1630.62 | 143035.80 | 605896.02 | 19005438.59 | 229101.73 |
| `flowPacketsPerSecond` | 0.00 | 0.03 | 16.76 | 735.89 | 7764.15 | 23529.41 | 1000000.00 | 6446.87 |
| `packetLengthMean` | 0.00 | 0.00 | 0.00 | 75.78 | 170.34 | 309.67 | 2521.12 | 76.75 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 0.00 | 51.25 | 127.56 | 199.05 | 11217.03 | 117.14 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.05 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.28 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.02 |

## Brute Force

- Total records: 84
- Top destination ports: 21 (76), 22 (8)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 1.00 | 2.00 | 2.00 | 3.00 | 20.70 | 361766.20 | 396897.00 | 34269.79 |
| `totalFwdPackets` | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 22.00 | 22.00 | 2.98 |
| `totalBwdPackets` | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 22.00 | 22.00 | 3.00 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 12014.40 | 17631.95 | 1244.75 |
| `flowPacketsPerSecond` | 110.86 | 666666.67 | 1000000.00 | 1000000.00 | 2000000.00 | 2000000.00 | 2000000.00 | 1009670.34 |
| `packetLengthMean` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 103.33 | 104.75 | 9.84 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 90.22 | 92.57 | 8.58 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Botnet

- Total records: 84
- Top destination ports: 8080 (84)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 453.00 | 498.00 | 671.00 | 10511.50 | 11057.30 | 12582.00 | 18453.00 | 5292.52 |
| `totalFwdPackets` | 2.00 | 2.00 | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.45 |
| `totalBwdPackets` | 0.00 | 0.00 | 0.00 | 4.00 | 4.00 | 4.00 | 4.00 | 1.81 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 0.00 | 42592.75 | 45223.71 | 47284.80 | 50929.04 | 19078.22 |
| `flowPacketsPerSecond` | 379.34 | 665.94 | 2980.65 | 4016.06 | 4252.61 | 4316.87 | 4415.01 | 2355.17 |
| `packetLengthMean` | 0.00 | 0.00 | 0.00 | 56.88 | 56.88 | 56.88 | 58.25 | 25.75 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 0.00 | 108.67 | 108.67 | 108.67 | 108.67 | 49.16 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `ackFlagCount` | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.55 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.45 |

## DoS

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 127672.00 | 3084326.50 | 5979329.00 | 16115858.00 | 102514203.60 | 107163316.00 | 108382033.00 | 22795625.00 |
| `totalFwdPackets` | 2.00 | 2.00 | 4.00 | 5.00 | 10.40 | 14.00 | 15.00 | 4.58 |
| `totalBwdPackets` | 0.00 | 0.00 | 3.00 | 4.00 | 4.00 | 4.00 | 4.00 | 2.33 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 105.81 | 248.43 | 299.26 | 383.92 | 11795.85 | 467.48 |
| `flowPacketsPerSecond` | 0.03 | 0.42 | 1.03 | 1.59 | 1.60 | 2.48 | 62.66 | 3.07 |
| `packetLengthMean` | 0.00 | 0.00 | 125.44 | 145.72 | 163.31 | 168.20 | 241.44 | 95.02 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 85.25 | 117.50 | 178.30 | 211.75 | 262.82 | 81.28 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.02 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.34 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## DDoS

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 597567.00 | 1150131.50 | 1406126.00 | 1633635.50 | 1856970.80 | 31657746.80 | 85558111.00 | 4362895.88 |
| `totalFwdPackets` | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.92 |
| `totalBwdPackets` | 0.00 | 4.00 | 4.00 | 4.00 | 4.00 | 4.00 | 4.00 | 3.66 |
| `flowBytesPerSecond` | 0.00 | 599.74 | 699.80 | 855.56 | 1096.92 | 1256.99 | 1646.68 | 719.67 |
| `flowPacketsPerSecond` | 0.02 | 4.27 | 4.98 | 6.09 | 7.80 | 8.94 | 11.71 | 5.14 |
| `packetLengthMean` | 0.00 | 123.00 | 123.00 | 123.00 | 123.00 | 123.00 | 123.00 | 112.63 |
| `fwdPacketLengthMean` | 0.00 | 6.67 | 6.67 | 6.67 | 6.67 | 6.67 | 6.67 | 6.10 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 0.08 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.92 |

## Web Attack

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 6.00 | 160.00 | 5002223.00 | 5014576.50 | 56831455.20 | 57091783.90 | 63603693.00 | 13381993.60 |
| `totalFwdPackets` | 2.00 | 2.00 | 4.00 | 5.00 | 153.80 | 203.00 | 203.00 | 38.72 |
| `totalBwdPackets` | 0.00 | 0.00 | 3.00 | 4.00 | 104.00 | 104.00 | 109.00 | 22.66 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 179.13 | 476.57 | 2682.38 | 4313.88 | 4879.85 | 769.73 |
| `flowPacketsPerSecond` | 0.68 | 1.60 | 5.57 | 15467.17 | 93581.78 | 152747.25 | 333333.33 | 25638.04 |
| `packetLengthMean` | 0.00 | 0.00 | 99.67 | 269.11 | 565.73 | 798.66 | 808.51 | 180.13 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 97.00 | 161.50 | 341.19 | 359.44 | 359.44 | 109.48 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.48 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.52 |

## Infiltration

- Total records: 83
- Top destination ports: 443 (25), 53 (24), 445 (5), 80 (4), 3389 (4), 139 (2), 0 (1), 31097 (1), 35972 (1), 52162 (1)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 0.00 | 182.00 | 1385.00 | 446968.00 | 60920828.40 | 115495861.90 | 118694744.00 | 12859749.66 |
| `totalFwdPackets` | 1.00 | 1.00 | 2.00 | 5.00 | 12.60 | 16.90 | 41.00 | 4.63 |
| `totalBwdPackets` | 0.00 | 0.50 | 1.00 | 4.50 | 12.00 | 14.90 | 70.00 | 4.39 |
| `flowBytesPerSecond` | 0.00 | 0.00 | 392.65 | 82717.04 | 180301.56 | 338488.42 | 403141.36 | 55306.94 |
| `flowPacketsPerSecond` | 0.00 | 18.68 | 1051.52 | 12757.09 | 99047.62 | 117647.06 | 2000000.00 | 44861.03 |
| `packetLengthMean` | 0.00 | 0.00 | 52.33 | 81.02 | 221.84 | 292.21 | 547.78 | 76.21 |
| `fwdPacketLengthMean` | 0.00 | 0.00 | 32.00 | 50.71 | 113.68 | 143.00 | 183.36 | 39.40 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.02 |
| `ackFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.37 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.27 |

