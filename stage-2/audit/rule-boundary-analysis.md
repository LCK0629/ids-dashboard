# Stage 2B Rule Boundary Analysis

Stage 2B analyses current rule boundaries without changing thresholds. Ground truth is joined only for audit reporting.

## SIG-FTP-BRUTE-FORCE

- Predicted attack type: Brute Force
- Total records matched: 76
- Malicious records matched: 76
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 0
- Confidence level: Moderate
- Interpretation: FTP Brute Force Flow Pattern matched 76 current sample records using feature-only conditions.
- Limitation: Cannot inspect FTP login payloads or failed login responses.
- Action recommendation: Keep as prototype heuristic

Current conditions:

- `protocol=TCP`
- `destinationPort=21`
- `flowPacketsPerSecond {"min":10}`
- `totalFwdPackets {"min":10}`
- `flowDuration {"max":5000000}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Brute Force: 76/84 (90.48%)

Benign near-miss examples:

- none

## SIG-SSH-BRUTE-FORCE

- Predicted attack type: Brute Force
- Total records matched: 8
- Malicious records matched: 8
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 11
- Confidence level: Moderate
- Interpretation: SSH Brute Force Flow Pattern matched 8 current sample records using feature-only conditions.
- Limitation: Cannot inspect SSH authentication failure details.
- Action recommendation: Keep as prototype heuristic

Current conditions:

- `protocol=TCP`
- `destinationPort=22`
- `flowPacketsPerSecond {"min":10}`
- `totalFwdPackets {"min":10}`
- `flowDuration {"max":5000000}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Brute Force: 8/84 (9.52%)

Benign near-miss examples:

- AL-0066: protocol matched (TCP); destinationPort matched (22); flowDuration matched (1160000)
- AL-0074: protocol matched (TCP); destinationPort matched (22); flowDuration matched (1280000)
- AL-0105: protocol matched (TCP); destinationPort matched (22); flowDuration matched (800000)
- AL-0111: protocol matched (TCP); destinationPort matched (22); flowDuration matched (1520000)
- AL-0131: protocol matched (TCP); destinationPort matched (22); flowDuration matched (1400000)

## SIG-DOS-HIGH-RATE-FLOW

- Predicted attack type: DoS
- Total records matched: 83
- Malicious records matched: 83
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 500
- Confidence level: Moderate
- Interpretation: High Rate DoS Flow Pattern matched 83 current sample records using feature-only conditions.
- Limitation: High-rate legitimate traffic can also match this pattern.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `flowPacketsPerSecond {"min":650,"max":899}`
- `totalFwdPackets {"min":80}`
- `totalBwdPackets {"max":10}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- DoS: 83/83 (100.00%)

Benign near-miss examples:

- AL-0001: flowPacketsPerSecond close to max (3 vs 899); totalBwdPackets matched (3)
- AL-0002: flowPacketsPerSecond close to max (4 vs 899); totalBwdPackets matched (2)
- AL-0003: flowPacketsPerSecond close to max (5 vs 899); totalBwdPackets matched (3)
- AL-0004: protocol matched (TCP); flowPacketsPerSecond close to max (2 vs 899); totalBwdPackets matched (2)
- AL-0005: flowPacketsPerSecond close to max (3 vs 899); totalBwdPackets matched (3)

## SIG-DDOS-HIGH-RATE-FLOW

- Predicted attack type: DDoS
- Total records matched: 83
- Malicious records matched: 83
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 500
- Confidence level: Moderate
- Interpretation: Distributed High Rate Flow Pattern matched 83 current sample records using feature-only conditions.
- Limitation: A single flow row cannot prove distributed source behavior.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `flowPacketsPerSecond {"min":900}`
- `totalFwdPackets {"min":120}`
- `totalBwdPackets {"max":8}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- DDoS: 83/83 (100.00%)

Benign near-miss examples:

- AL-0001: totalBwdPackets matched (3)
- AL-0002: totalBwdPackets matched (2)
- AL-0003: totalBwdPackets matched (3)
- AL-0004: protocol matched (TCP); totalBwdPackets matched (2)
- AL-0005: totalBwdPackets matched (3)

## SIG-BOTNET-BEACON-FLOW

- Predicted attack type: Botnet
- Total records matched: 84
- Malicious records matched: 84
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 500
- Confidence level: Experimental
- Interpretation: Botnet Beacon-Like Flow Pattern matched 84 current sample records using feature-only conditions.
- Limitation: Reliable botnet detection often needs host history, C2 indicators, or destination reputation.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `flowDuration {"min":10000000}`
- `flowPacketsPerSecond {"min":20,"max":120}`
- `totalFwdPackets {"min":20}`
- `totalBwdPackets {"max":15}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Botnet: 84/84 (100.00%)

Benign near-miss examples:

- AL-0001: flowPacketsPerSecond close to max (3 vs 120); totalBwdPackets matched (3)
- AL-0002: flowPacketsPerSecond close to max (4 vs 120); totalBwdPackets matched (2)
- AL-0003: flowPacketsPerSecond close to max (5 vs 120); totalBwdPackets matched (3)
- AL-0004: flowPacketsPerSecond close to max (2 vs 120); totalBwdPackets matched (2)
- AL-0005: flowPacketsPerSecond close to max (3 vs 120); totalBwdPackets matched (3)

## SIG-WEB-ATTACK-FLOW

- Predicted attack type: Web Attack
- Total records matched: 83
- Malicious records matched: 83
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 125
- Confidence level: Experimental
- Interpretation: Suspicious Web Flow Pattern matched 83 current sample records using feature-only conditions.
- Limitation: Flow-level rules cannot inspect URLs, SQL strings, XSS payloads, or HTTP parameters.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `destinationPort {"oneOf":[80,443]}`
- `packetLengthMean {"min":300}`
- `fwdPacketLengthMean {"min":250}`
- `flowDuration {"max":5000000}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Web Attack: 83/83 (100.00%)

Benign near-miss examples:

- AL-0016: protocol matched (TCP); destinationPort matched (80); flowDuration matched (1040000)
- AL-0017: protocol matched (TCP); destinationPort matched (80); flowDuration matched (1160000)
- AL-0020: protocol matched (TCP); destinationPort matched (80); flowDuration matched (1520000)
- AL-0031: protocol matched (TCP); destinationPort matched (443); flowDuration matched (1160000)
- AL-0034: protocol matched (TCP); destinationPort matched (80); flowDuration matched (1520000)

## SIG-INFILTRATION-LONG-FLOW

- Predicted attack type: Infiltration
- Total records matched: 83
- Malicious records matched: 83
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 0
- Confidence level: Weak
- Interpretation: Long Duration Infiltration-Like Flow Pattern matched 83 current sample records using feature-only conditions.
- Limitation: Infiltration is context-dependent and difficult to detect with flow features alone.
- Action recommendation: Needs richer features

Current conditions:

- `flowDuration {"min":20000000}`
- `totalBwdPackets {"min":20}`
- `flowBytesPerSecond {"min":10000}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Infiltration: 83/83 (100.00%)

Benign near-miss examples:

- none

