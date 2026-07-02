# FYP Proposal Notes

## Project Title

Human-in-the-Loop Intrusion Detection Dashboard

## Problem Statement

Traditional intrusion detection systems often produce a large number of alerts, including many false positives. Security administrators may spend significant time reviewing low-priority or irrelevant alerts, which can delay the identification of real threats.

This project aims to improve intrusion alert triage by integrating human feedback into the dashboard. Administrator responses will be used to adjust alert priority, highlight more relevant threats, and reduce repeated false positives.

## Research Question

How can human feedback be incorporated into an intrusion detection dashboard to reduce false positives and improve the usability of security alert triage?

## Objectives

- Design and develop an intrusion detection dashboard for viewing security alerts.
- Provide feedback controls for administrators to label alerts.
- Use feedback to adapt alert priority or risk scoring.
- Visualize alerts through charts, tables, and summary views.
- Evaluate the effectiveness of the dashboard in reducing false positives or improving alert handling.

## Expected Outcome

The expected outcome is a functional prototype dashboard that demonstrates how human feedback can improve intrusion alert management. The system should allow users to inspect alerts, label them, and observe how the dashboard adapts future alert prioritization based on feedback.

## Scope

The project will focus on the dashboard interface, feedback workflow, and adaptive alert prioritization logic. It does not need to build a full production-grade intrusion detection engine from scratch. Public datasets or simulated IDS alert logs may be used as input data.

The project will use a hybrid detection pipeline. Known attack patterns will be represented through lightweight flow-based signature rules, while ML-based detection will later be implemented using an XGBoost classifier trained on CSE-CIC-IDS2018 flow features. The dashboard will fuse these outputs and allow analyst feedback to adjust alert priority.

## Personal Notes

- 中文备注：重点不是做完整 IDS，而是做一个能展示 human-in-the-loop 概念的 dashboard prototype。
- Demo 时最好能展示 feedback 前后 alert ranking 的变化。
