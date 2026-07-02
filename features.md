# Feature Plan

## Prototype Status

The current prototype is frontend-only and uses hardcoded IDS alerts. It is designed to show the final dashboard experience without requiring a backend, database, or live IDS integration.

## Dashboard Overview

- [x] Show total alerts.
- [x] Show high-risk alerts.
- [x] Show false positive count.
- [x] Show alerts requiring review.
- [x] Show recent alert activity through hardcoded timestamps.

## Alert Table

- [x] Display alert ID.
- [x] Display timestamp.
- [x] Display source IP address.
- [x] Display destination IP address.
- [x] Display protocol.
- [x] Display port.
- [x] Display attack type.
- [x] Display severity.
- [x] Display confidence score.
- [x] Display current feedback status.
- [x] Display one-line trigger reason.

## Alert Details

- [x] Show full alert information.
- [x] Show related network information.
- [x] Show previous similar alerts.
- [x] Show suggested priority or risk level.
- [x] Show trigger reason, risk factors, evidence, and recommended action.

## Human Feedback Controls

- [x] Allow administrator to mark an alert as true positive.
- [x] Allow administrator to mark an alert as false positive.
- [x] Allow administrator to mark an alert as suspicious.
- [x] Allow administrator to mark an alert as benign.
- [ ] Allow administrator to mark an alert as needs review.
- [ ] Store feedback history for later analysis.

## Adaptive Scoring

- [x] Adjust alert priority based on feedback.
- [x] Reduce priority for repeated false positive patterns.
- [x] Increase priority for patterns confirmed as true threats.
- [x] Show updated risk score in the dashboard.
- [x] Keep scoring logic understandable and explainable.

## Visualisations

- [ ] Alert trend over time.
- [x] Attack type distribution.
- [x] Severity distribution.
- [ ] Top source IP addresses.
- [ ] Top destination IP addresses.
- [x] Feedback impact chart.

## Report View

- [ ] Summarize total alerts reviewed.
- [ ] Summarize feedback categories.
- [ ] Summarize improvement after feedback.
- [ ] Export or display basic evaluation results.
