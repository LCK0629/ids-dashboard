# Signature Rule Rationale

## 1. Purpose

This document records how the Stage 2 flow-based signature rules were derived.

- The rules are manually designed prototype heuristics.
- They are based on IDS signature-detection principles, common network attack behavior, and observable CSE-CIC-IDS2018 flow features.
- They are not automatically learned ML rules.
- They are not copied Snort or Suricata packet-payload rules.
- They do not use ground-truth labels during runtime matching.

The purpose is to make the current Stage 2 rules explainable and defensible as a prototype IDS layer, while avoiding claims that the rules are globally optimal or production-ready.

## 2. Design Principles

The Stage 2 rules follow these design principles:

- Use only observable flow-level features.
- Avoid answer-derived fields such as `Label`, `attackType`, `mappedAttackType`, `groundTruth`, `severity`, and `similarityKey`.
- Keep rules interpretable for SOC analysts.
- Match known attack-like behavior rather than unknown anomaly behavior.
- Treat thresholds as prototype heuristic values.
- Evaluate rules after prediction by joining ground truth only for measurement.

These principles keep Stage 2 aligned with signature-based IDS ideas while avoiding label leakage from the dataset answers.

## 3. Allowed Feature Basis

The current rules are based on observable flow-level fields from `stage-1/data/processed/flow-feature-sample.csv`.

- `protocol`: network protocol used by the flow, such as TCP or UDP.
- `destinationPort`: destination service port being targeted, such as FTP port 21, SSH port 22, or web ports 80/443.
- `flowDuration`: duration of the flow; useful for identifying short brute-force-like attempts or longer beacon-like flows.
- `totalFwdPackets`: number of forward packets from source to destination; useful for estimating source-to-target pressure.
- `totalBwdPackets`: number of backward packets from destination to source; useful for identifying response imbalance.
- `flowBytesPerSecond`: byte rate of the flow; useful for identifying sustained transfer behavior.
- `flowPacketsPerSecond`: packet rate of the flow; useful for high-rate DoS/DDoS-like traffic.
- `packetLengthMean`: average packet length across the flow; useful for spotting larger request or payload-like flow patterns.
- `fwdPacketLengthMean`: average forward packet length; useful for request-heavy client-to-server behavior.
- `synFlagCount`: number of SYN flags; useful for TCP connection attempt patterns.
- `ackFlagCount`: number of ACK flags; useful for established TCP communication patterns.
- `finFlagCount`: number of FIN flags; useful for connection termination behavior.
- `rstFlagCount`: number of RST flags; useful for reset or abnormal termination behavior.

These features are observable from flow records and do not directly reveal the true attack label.

## 4. Rule-by-Rule Rationale

### SIG-FTP-BRUTE-FORCE

- Rule ID: `SIG-FTP-BRUTE-FORCE`
- Predicted attack type: `Brute Force`
- Rule conditions:
  - `protocol = TCP`
  - `destinationPort = 21`
  - `flowPacketsPerSecond >= 10`
  - `totalFwdPackets >= 10`
  - `flowDuration <= 5000000`
- Why each condition is used:
  - FTP control traffic commonly uses TCP port 21.
  - Brute-force-like attempts may create repeated short TCP flows.
  - Elevated packet rate and enough forward packets indicate repeated client-side activity.
  - Short flow duration approximates repeated login attempts.
- Why the rule is reasonable as a flow-level heuristic: it represents a known service-specific brute-force pattern using only port, protocol, packet rate, packet count, and duration.
- Limitation: it cannot inspect FTP login payload or failed login messages.
- Confidence level: Moderate.

### SIG-SSH-BRUTE-FORCE

- Rule ID: `SIG-SSH-BRUTE-FORCE`
- Predicted attack type: `Brute Force`
- Rule conditions:
  - `protocol = TCP`
  - `destinationPort = 22`
  - `flowPacketsPerSecond >= 10`
  - `totalFwdPackets >= 10`
  - `flowDuration <= 5000000`
- Why each condition is used:
  - SSH commonly uses TCP port 22.
  - SSH brute-force attempts may create repeated short TCP flows.
  - Elevated packet rate and forward packet count provide flow-level evidence.
  - Short flow duration helps approximate repeated connection or authentication attempts.
- Why the rule is reasonable as a flow-level heuristic: it captures a known SSH service-targeting pattern without reading the true dataset label.
- Limitation: it cannot inspect SSH authentication failure details.
- Confidence level: Moderate.

### SIG-DOS-HIGH-RATE-FLOW

- Rule ID: `SIG-DOS-HIGH-RATE-FLOW`
- Predicted attack type: `DoS`
- Rule conditions:
  - `protocol = TCP`
  - `flowPacketsPerSecond >= 650`
  - `flowPacketsPerSecond <= 899`
  - `totalFwdPackets >= 80`
  - `totalBwdPackets <= 10`
- Why each condition is used:
  - DoS-like traffic often creates high packet-rate flows.
  - High forward packet count suggests strong source-to-target pressure.
  - Low backward packet count may indicate limited target response.
  - The upper packet-rate boundary separates this prototype DoS rule from the higher-rate DDoS rule.
- Why the rule is reasonable as a flow-level heuristic: it captures high-rate, one-direction-heavy TCP behavior associated with denial-of-service pressure.
- Limitation: high-rate legitimate traffic can also match this pattern.
- Confidence level: Moderate.

### SIG-DDOS-HIGH-RATE-FLOW

- Rule ID: `SIG-DDOS-HIGH-RATE-FLOW`
- Predicted attack type: `DDoS`
- Rule conditions:
  - `protocol = TCP`
  - `flowPacketsPerSecond >= 900`
  - `totalFwdPackets >= 120`
  - `totalBwdPackets <= 8`
- Why each condition is used:
  - DDoS-like traffic can produce very high packet rates and strong forward traffic.
  - The rule uses a higher packet-rate threshold than the DoS rule.
  - Low backward packet count indicates traffic imbalance.
- Why the rule is reasonable as a flow-level heuristic: it represents more extreme high-rate traffic than the DoS rule.
- Limitation: a single flow row cannot prove distributed source behavior.
- Confidence level: Moderate.

### SIG-BOTNET-BEACON-FLOW

- Rule ID: `SIG-BOTNET-BEACON-FLOW`
- Predicted attack type: `Botnet`
- Rule conditions:
  - `flowDuration >= 10000000`
  - `flowPacketsPerSecond >= 20`
  - `flowPacketsPerSecond <= 120`
  - `totalFwdPackets >= 20`
  - `totalBwdPackets <= 15`
- Why each condition is used:
  - Botnet communication may appear as longer-lived beacon-like flows.
  - Moderate packet rate is used instead of very high packet rate because beaconing is usually not the same as DoS flooding.
  - Minimum forward packets indicate repeated outbound communication.
  - Low backward packets suggest limited response.
- Why the rule is reasonable as a flow-level heuristic: it models a repeated communication pattern that is distinct from high-rate flooding.
- Limitation: reliable botnet detection often requires host history, C2 indicators, or destination reputation.
- Confidence level: Experimental.

### SIG-WEB-ATTACK-FLOW

- Rule ID: `SIG-WEB-ATTACK-FLOW`
- Predicted attack type: `Web Attack`
- Rule conditions:
  - `protocol = TCP`
  - `destinationPort` is `80` or `443`
  - `packetLengthMean >= 300`
  - `fwdPacketLengthMean >= 250`
  - `flowDuration <= 5000000`
- Why each condition is used:
  - Web attacks commonly target HTTP/HTTPS services on ports 80/443.
  - Larger packet length values may indicate request-heavy or payload-heavy web flows.
  - Short flow duration can approximate short exploit/request attempts.
- Why the rule is reasonable as a flow-level heuristic: it uses service targeting and request-size behavior to approximate suspicious web activity.
- Limitation: flow-level rules cannot inspect URLs, SQL strings, XSS payloads, or HTTP parameters.
- Confidence level: Experimental.

### SIG-INFILTRATION-LONG-FLOW

- Rule ID: `SIG-INFILTRATION-LONG-FLOW`
- Predicted attack type: `Infiltration`
- Rule conditions:
  - `flowDuration >= 20000000`
  - `totalBwdPackets >= 20`
  - `flowBytesPerSecond >= 10000`
- Why each condition is used:
  - Infiltration-like activity may involve longer flows and sustained data transfer.
  - Flow bytes per second gives a rough indication of ongoing transfer.
  - Backward packets may indicate interactive or data-transfer behavior.
- Why the rule is reasonable as a flow-level heuristic: it approximates sustained, interactive, data-transfer-like behavior using only flow statistics.
- Limitation: infiltration is highly context-dependent and difficult to detect with flow features alone.
- Confidence level: Weak / Experimental.

## 5. Why the Current Rules Achieved Perfect Results on the Current Sample

The current Stage 1 sample is balanced and structured. It contains 500 benign records and 500 malicious records distributed across the selected attack categories.

The rules were designed to cover the known attack categories present in the sample. The feature distributions in the current sample may separate benign and malicious records clearly, especially because the sample is controlled and prepared for Stage 2 demonstration.

Perfect results on this sample do not prove production-level IDS performance. The result is useful as a Stage 2 prototype demonstration, not as a final scientific conclusion.

The current Stage 2 evaluation shows that the prototype rules fully cover the selected Stage 1 sample without benign false hits. This should be interpreted as successful prototype coverage on a controlled sample, not as evidence that the rules are globally optimal or production-ready.

## 6. Why No Threshold Tuning Was Performed Yet

Threshold tuning on the same 1000-record sample could overfit the rules to the current sample. Stage 2 is intended to remain an interpretable signature-based layer, while Stage 3 will provide the formal machine-learning component.

At this stage, the priority is to document rule rationale and evaluate current behavior, not maximize F1 through sample-specific tuning.

The thresholds are intentionally treated as prototype heuristic thresholds. They are documented and evaluated, but not optimized on the same sample used for reporting, in order to avoid overstating the generality of the current results.

## 7. Future Validation Plan

The next improvement path is:

- Perform feature distribution audit.
- Compare benign and attack-type distributions for rule features.
- Identify near-miss benign flows.
- Test rules on a separate held-out CSE-CIC-IDS2018 sample.
- Decide whether each rule should be kept, adjusted, or marked weak.
- Consider threshold calibration only with calibration/validation split.

This keeps the current prototype useful while making the route toward stronger evaluation explicit.

## 8. Stage 2B Audit Support

Stage 2B adds an audit script that reviews the current Stage 1 feature sample against the existing Stage 2 signature rules.

The audit produces feature distribution summaries by true attack type, rule boundary analysis, benign near-miss reporting, and a rule review matrix. These outputs support report writing and help explain why each rule appears reasonable on the current sample.

The audit does not replace the manual rule rationale in this document. It also does not prove that the rules are globally optimal, and it does not perform threshold tuning or rule optimisation.

## 9. Suggested Report Wording

The Stage 2 signature rules were manually designed as flow-level heuristic rules. Their structure is based on signature-based IDS principles, common network attack behavior, and observable CSE-CIC-IDS2018 flow features such as destination port, packet rate, flow duration, and packet counts. The rules do not use ground-truth labels as detection input. Although the current rules achieved full coverage on the selected Stage 1 sample, this result is treated as prototype evidence only. The thresholds are not claimed to be globally optimal and require further validation using feature distribution analysis and held-out samples.
