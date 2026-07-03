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
| `flowDuration` | 800000.00 | 920000.00 | 1160000.00 | 1400000.00 | 1520000.00 | 1520000.00 | 1520000.00 | 1159280.00 |
| `totalFwdPackets` | 3.00 | 3.00 | 4.00 | 5.00 | 5.00 | 5.00 | 5.00 | 3.86 |
| `totalBwdPackets` | 2.00 | 2.00 | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.43 |
| `flowBytesPerSecond` | 250.00 | 280.00 | 340.00 | 400.00 | 430.00 | 430.00 | 430.00 | 339.82 |
| `flowPacketsPerSecond` | 2.00 | 2.00 | 3.00 | 4.00 | 5.00 | 5.00 | 5.00 | 3.29 |
| `packetLengthMean` | 75.00 | 77.00 | 81.00 | 85.00 | 87.00 | 87.00 | 87.00 | 80.99 |
| `fwdPacketLengthMean` | 60.00 | 62.00 | 66.00 | 70.00 | 72.00 | 72.00 | 72.00 | 65.99 |
| `synFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `ackFlagCount` | 1.00 | 1.00 | 1.00 | 2.00 | 2.00 | 2.00 | 2.00 | 1.43 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Brute Force

- Total records: 84
- Top destination ports: 21 (76), 22 (8)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 1200000.00 | 1300000.00 | 1500000.00 | 1700000.00 | 1800000.00 | 1800000.00 | 1800000.00 | 1500000.00 |
| `totalFwdPackets` | 14.00 | 15.00 | 17.00 | 19.00 | 20.00 | 20.00 | 20.00 | 17.00 |
| `totalBwdPackets` | 2.00 | 2.00 | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.43 |
| `flowBytesPerSecond` | 2200.00 | 2280.00 | 2440.00 | 2600.00 | 2680.00 | 2680.00 | 2680.00 | 2440.00 |
| `flowPacketsPerSecond` | 16.00 | 17.00 | 19.00 | 21.00 | 22.00 | 22.00 | 22.00 | 19.00 |
| `packetLengthMean` | 92.00 | 93.00 | 95.00 | 97.00 | 98.00 | 98.00 | 98.00 | 95.00 |
| `fwdPacketLengthMean` | 86.00 | 87.00 | 89.00 | 91.00 | 92.00 | 92.00 | 92.00 | 89.00 |
| `synFlagCount` | 2.00 | 2.00 | 3.00 | 4.00 | 4.00 | 4.00 | 4.00 | 2.86 |
| `ackFlagCount` | 1.00 | 1.00 | 1.00 | 2.00 | 2.00 | 2.00 | 2.00 | 1.43 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Botnet

- Total records: 84
- Top destination ports: 8080 (84)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 12000000.00 | 12800000.00 | 14400000.00 | 16000000.00 | 16800000.00 | 16800000.00 | 16800000.00 | 14400000.00 |
| `totalFwdPackets` | 26.00 | 27.00 | 29.00 | 31.00 | 32.00 | 32.00 | 32.00 | 29.00 |
| `totalBwdPackets` | 9.00 | 9.00 | 10.00 | 11.00 | 12.00 | 12.00 | 12.00 | 10.29 |
| `flowBytesPerSecond` | 2600.00 | 2720.00 | 2960.00 | 3200.00 | 3320.00 | 3320.00 | 3320.00 | 2960.00 |
| `flowPacketsPerSecond` | 35.00 | 37.00 | 41.00 | 45.00 | 47.00 | 47.00 | 47.00 | 41.00 |
| `packetLengthMean` | 140.00 | 142.00 | 146.00 | 150.00 | 152.00 | 152.00 | 152.00 | 146.00 |
| `fwdPacketLengthMean` | 120.00 | 122.00 | 126.00 | 130.00 | 132.00 | 132.00 | 132.00 | 126.00 |
| `synFlagCount` | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| `ackFlagCount` | 8.00 | 8.00 | 9.00 | 10.00 | 10.00 | 10.00 | 10.00 | 8.86 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## DoS

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 900000.00 | 950000.00 | 1050000.00 | 1150000.00 | 1200000.00 | 1200000.00 | 1200000.00 | 1050000.00 |
| `totalFwdPackets` | 95.00 | 97.00 | 101.00 | 105.00 | 107.00 | 107.00 | 107.00 | 101.00 |
| `totalBwdPackets` | 3.00 | 3.00 | 4.00 | 5.00 | 5.00 | 5.00 | 5.00 | 3.87 |
| `flowBytesPerSecond` | 85000.00 | 86500.00 | 89500.00 | 92500.00 | 94000.00 | 94000.00 | 94000.00 | 89500.00 |
| `flowPacketsPerSecond` | 720.00 | 738.00 | 774.00 | 810.00 | 828.00 | 828.00 | 828.00 | 774.00 |
| `packetLengthMean` | 230.00 | 233.00 | 239.00 | 245.00 | 248.00 | 248.00 | 248.00 | 239.00 |
| `fwdPacketLengthMean` | 210.00 | 213.00 | 219.00 | 225.00 | 228.00 | 228.00 | 228.00 | 219.00 |
| `synFlagCount` | 8.00 | 8.00 | 9.00 | 10.00 | 11.00 | 11.00 | 11.00 | 9.27 |
| `ackFlagCount` | 2.00 | 2.00 | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.42 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## DDoS

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 800000.00 | 845000.00 | 935000.00 | 1025000.00 | 1070000.00 | 1070000.00 | 1070000.00 | 935542.17 |
| `totalFwdPackets` | 135.00 | 138.00 | 144.00 | 150.00 | 153.00 | 153.00 | 153.00 | 144.04 |
| `totalBwdPackets` | 2.00 | 2.00 | 3.00 | 4.00 | 4.00 | 4.00 | 4.00 | 2.84 |
| `flowBytesPerSecond` | 150000.00 | 152000.00 | 156000.00 | 160000.00 | 162000.00 | 162000.00 | 162000.00 | 156024.10 |
| `flowPacketsPerSecond` | 960.00 | 982.00 | 1026.00 | 1070.00 | 1092.00 | 1092.00 | 1092.00 | 1026.27 |
| `packetLengthMean` | 260.00 | 264.00 | 272.00 | 280.00 | 284.00 | 284.00 | 284.00 | 272.05 |
| `fwdPacketLengthMean` | 240.00 | 244.00 | 252.00 | 260.00 | 264.00 | 264.00 | 264.00 | 252.05 |
| `synFlagCount` | 10.00 | 10.00 | 11.00 | 13.00 | 14.00 | 14.00 | 14.00 | 11.57 |
| `ackFlagCount` | 2.00 | 2.00 | 2.00 | 3.00 | 3.00 | 3.00 | 3.00 | 2.43 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Web Attack

- Total records: 83
- Top destination ports: 80 (83)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 1800000.00 | 1890000.00 | 2070000.00 | 2250000.00 | 2340000.00 | 2340000.00 | 2340000.00 | 2072168.67 |
| `totalFwdPackets` | 18.00 | 19.00 | 21.00 | 23.00 | 24.00 | 24.00 | 24.00 | 21.02 |
| `totalBwdPackets` | 12.00 | 12.00 | 13.00 | 14.00 | 14.00 | 14.00 | 14.00 | 12.86 |
| `flowBytesPerSecond` | 18000.00 | 18500.00 | 19500.00 | 20500.00 | 21000.00 | 21000.00 | 21000.00 | 19512.05 |
| `flowPacketsPerSecond` | 90.00 | 94.00 | 102.00 | 110.00 | 114.00 | 114.00 | 114.00 | 102.10 |
| `packetLengthMean` | 360.00 | 367.00 | 381.00 | 395.00 | 402.00 | 402.00 | 402.00 | 381.17 |
| `fwdPacketLengthMean` | 330.00 | 337.00 | 351.00 | 365.00 | 372.00 | 372.00 | 372.00 | 351.17 |
| `synFlagCount` | 1.00 | 1.00 | 1.00 | 2.00 | 2.00 | 2.00 | 2.00 | 1.42 |
| `ackFlagCount` | 10.00 | 10.00 | 11.00 | 12.00 | 12.00 | 12.00 | 12.00 | 10.86 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Infiltration

- Total records: 83
- Top destination ports: 443 (25), 53 (24), 445 (5), 80 (4), 3389 (4), 139 (2), 0 (1), 31097 (1), 35972 (1), 52162 (1)

| Feature | Min | P25 | Median | P75 | P90 | P95 | Max | Mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `flowDuration` | 23000000.00 | 24000000.00 | 26000000.00 | 28000000.00 | 29000000.00 | 29000000.00 | 29000000.00 | 26036144.58 |
| `totalFwdPackets` | 45.00 | 47.00 | 51.00 | 55.00 | 57.00 | 57.00 | 57.00 | 51.07 |
| `totalBwdPackets` | 25.00 | 25.00 | 26.00 | 28.00 | 29.00 | 29.00 | 29.00 | 26.59 |
| `flowBytesPerSecond` | 13000.00 | 13700.00 | 15100.00 | 16500.00 | 17200.00 | 17200.00 | 17200.00 | 15125.30 |
| `flowPacketsPerSecond` | 65.00 | 68.00 | 74.00 | 80.00 | 83.00 | 83.00 | 83.00 | 74.11 |
| `packetLengthMean` | 440.00 | 448.00 | 464.00 | 480.00 | 488.00 | 488.00 | 488.00 | 464.29 |
| `fwdPacketLengthMean` | 410.00 | 418.00 | 434.00 | 450.00 | 458.00 | 458.00 | 458.00 | 434.29 |
| `synFlagCount` | 1.00 | 1.00 | 1.00 | 2.00 | 2.00 | 2.00 | 2.00 | 1.43 |
| `ackFlagCount` | 18.00 | 18.00 | 19.00 | 21.00 | 22.00 | 22.00 | 22.00 | 19.59 |
| `finFlagCount` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `rstFlagCount` | 1.00 | 1.00 | 1.00 | 2.00 | 2.00 | 2.00 | 2.00 | 1.43 |

