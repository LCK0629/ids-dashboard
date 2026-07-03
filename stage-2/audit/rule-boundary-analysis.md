# Stage 2B Rule Boundary Analysis

Stage 2B analyses current rule boundaries without changing thresholds. Ground truth is joined only for audit reporting.

## SIG-FTP-BRUTE-FORCE

- Predicted attack type: Brute Force
- Total records matched: 0
- Malicious records matched: 0
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 0
- Confidence level: Moderate
- Interpretation: FTP Brute Force Flow Pattern matched 0 current sample records using feature-only conditions.
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
- Brute Force: 0/84 (0.00%)

Benign near-miss examples:

- none

## SIG-SSH-BRUTE-FORCE

- Predicted attack type: Brute Force
- Total records matched: 11
- Malicious records matched: 8
- Benign records matched: 3
- Benign false match count: 3
- Benign near-miss count: 1
- Confidence level: Moderate
- Interpretation: SSH Brute Force Flow Pattern matched 11 current sample records using feature-only conditions.
- Limitation: Cannot inspect SSH authentication failure details.
- Action recommendation: Keep as prototype heuristic

Current conditions:

- `protocol=TCP`
- `destinationPort=22`
- `flowPacketsPerSecond {"min":10}`
- `totalFwdPackets {"min":10}`
- `flowDuration {"max":5000000}`

True attack type coverage:

- Benign: 3/500 (0.60%)
- Brute Force: 8/84 (9.52%)

Benign near-miss examples:

- AL-0074: protocol matched (TCP); destinationPort matched (22); flowPacketsPerSecond close to min (8.6144910276 vs 10)

## SIG-DOS-HIGH-RATE-FLOW

- Predicted attack type: DoS
- Total records matched: 0
- Malicious records matched: 0
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 12
- Confidence level: Moderate
- Interpretation: High Rate DoS Flow Pattern matched 0 current sample records using feature-only conditions.
- Limitation: High-rate legitimate traffic can also match this pattern.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `flowPacketsPerSecond {"min":650,"max":899}`
- `totalFwdPackets {"min":80}`
- `totalBwdPackets {"max":10}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- DoS: 0/83 (0.00%)

Benign near-miss examples:

- AL-0006: protocol matched (TCP); flowPacketsPerSecond close to min (536.1930294906 vs 650)
- AL-0022: protocol matched (TCP); flowPacketsPerSecond close to max (1025.9917920657 vs 899)
- AL-0032: protocol matched (TCP); flowPacketsPerSecond close to min (531.726338178 vs 650)
- AL-0063: protocol matched (TCP); flowPacketsPerSecond close to max (967.7419354839 vs 899)
- AL-0086: protocol matched (TCP); flowPacketsPerSecond close to max (930.8098045299 vs 899)

## SIG-DDOS-HIGH-RATE-FLOW

- Predicted attack type: DDoS
- Total records matched: 0
- Malicious records matched: 0
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 8
- Confidence level: Moderate
- Interpretation: Distributed High Rate Flow Pattern matched 0 current sample records using feature-only conditions.
- Limitation: A single flow row cannot prove distributed source behavior.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `flowPacketsPerSecond {"min":900}`
- `totalFwdPackets {"min":120}`
- `totalBwdPackets {"max":8}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- DDoS: 0/83 (0.00%)

Benign near-miss examples:

- AL-0013: protocol matched (TCP); flowPacketsPerSecond close to min (893.3889219774 vs 900)
- AL-0025: protocol matched (TCP); flowPacketsPerSecond close to min (807.7544426494 vs 900)
- AL-0044: protocol matched (TCP); flowPacketsPerSecond close to min (851.7887563884 vs 900)
- AL-0179: protocol matched (TCP); flowPacketsPerSecond close to min (853.7279453614 vs 900)
- AL-0227: protocol matched (TCP); flowPacketsPerSecond close to min (747.3841554559 vs 900)

## SIG-BOTNET-BEACON-FLOW

- Predicted attack type: Botnet
- Total records matched: 0
- Malicious records matched: 0
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 42
- Confidence level: Experimental
- Interpretation: Botnet Beacon-Like Flow Pattern matched 0 current sample records using feature-only conditions.
- Limitation: Reliable botnet detection often needs host history, C2 indicators, or destination reputation.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `flowDuration {"min":10000000}`
- `flowPacketsPerSecond {"min":20,"max":120}`
- `totalFwdPackets {"min":20}`
- `totalBwdPackets {"max":15}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Botnet: 0/84 (0.00%)

Benign near-miss examples:

- AL-0017: flowPacketsPerSecond close to min (16.8404034961 vs 20)
- AL-0020: flowPacketsPerSecond close to min (16.7361565835 vs 20)
- AL-0034: flowPacketsPerSecond close to min (16.8078879418 vs 20)
- AL-0041: flowPacketsPerSecond close to min (16.7658295628 vs 20)
- AL-0045: flowPacketsPerSecond close to min (16.7706095068 vs 20)

## SIG-WEB-ATTACK-FLOW

- Predicted attack type: Web Attack
- Total records matched: 4
- Malicious records matched: 0
- Benign records matched: 4
- Benign false match count: 4
- Benign near-miss count: 14
- Confidence level: Experimental
- Interpretation: Suspicious Web Flow Pattern matched 4 current sample records using feature-only conditions.
- Limitation: Flow-level rules cannot inspect URLs, SQL strings, XSS payloads, or HTTP parameters.
- Action recommendation: Keep but validate on held-out sample

Current conditions:

- `protocol=TCP`
- `destinationPort {"oneOf":[80,443]}`
- `packetLengthMean {"min":300}`
- `fwdPacketLengthMean {"min":250}`
- `flowDuration {"max":5000000}`

True attack type coverage:

- Benign: 4/500 (0.80%)
- Web Attack: 0/83 (0.00%)

Benign near-miss examples:

- AL-0038: protocol matched (TCP); destinationPort matched allowed value (80); flowDuration close to max (5072860 vs 5000000)
- AL-0271: protocol matched (TCP); destinationPort matched allowed value (80); flowDuration close to max (5402014 vs 5000000)
- AL-0295: protocol matched (TCP); destinationPort matched allowed value (80); flowDuration close to max (5551895 vs 5000000)
- AL-0301: protocol matched (TCP); destinationPort matched allowed value (443); packetLengthMean close to min (276.8235294118 vs 300)
- AL-0309: protocol matched (TCP); destinationPort matched allowed value (443); fwdPacketLengthMean close to min (222 vs 250)

## SIG-INFILTRATION-LONG-FLOW

- Predicted attack type: Infiltration
- Total records matched: 0
- Malicious records matched: 0
- Benign records matched: 0
- Benign false match count: 0
- Benign near-miss count: 5
- Confidence level: Weak
- Interpretation: Long Duration Infiltration-Like Flow Pattern matched 0 current sample records using feature-only conditions.
- Limitation: Infiltration is context-dependent and difficult to detect with flow features alone.
- Action recommendation: Needs richer features

Current conditions:

- `flowDuration {"min":20000000}`
- `totalBwdPackets {"min":20}`
- `flowBytesPerSecond {"min":10000}`

True attack type coverage:

- Benign: 0/500 (0.00%)
- Infiltration: 0/83 (0.00%)

Benign near-miss examples:

- AL-0300: flowBytesPerSecond close to min (9121.8815254424 vs 10000)
- AL-0325: flowBytesPerSecond close to min (9117.8073658803 vs 10000)
- AL-0396: flowBytesPerSecond close to min (9592.3261390887 vs 10000)
- AL-0401: flowBytesPerSecond close to min (9653.830913872 vs 10000)
- AL-0499: flowBytesPerSecond close to min (9237.8752886836 vs 10000)

