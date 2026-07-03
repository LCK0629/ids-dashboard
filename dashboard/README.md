# Stage 6 React Dashboard Integration

## Purpose

This dashboard visualises Stage 5 feedback-adjusted IDS alerts.

It is the formal React dashboard integration layer for the staged Human-in-the-Loop IDS project.

The Stage 6 layout was upgraded using the uploaded SOC-style HTML prototype as a visual reference. The implementation remains React + Vite + TypeScript; the uploaded HTML was used as layout inspiration, not as runtime code.

## Data Source

The dashboard reads static JSON copies from:

```txt
dashboard/src/data/feedback-adjusted-alerts.sample.json
dashboard/src/data/feedback-evaluation-summary.json
dashboard/src/data/fusion-evaluation-summary.json
```

These files were copied from:

```txt
stage-5/outputs/feedback-adjusted-alerts.sample.json
stage-5/evaluation/feedback-evaluation-summary.json
stage-4/evaluation/fusion-evaluation-summary.json
```

The original Stage 4 and Stage 5 outputs are not moved. If the pipeline outputs change later, refresh the dashboard copies from the source files.

## How to Run

From this folder:

```powershell
npm install
npm run dev
```

For a production build:

```powershell
npm run build
```

## Dashboard Features

- KPI cards for Stage 5 feedback and review impact.
- Filter bar for review-required, adjusted, high-risk, guardrail, benign, and malicious views.
- Alert queue sorted by feedback-adjusted `currentRiskScore`.
- Alert detail panel showing signature evidence, ML prediction, fusion evidence, and feedback adjustment.
- Score comparison between Stage 4 `fusionRiskScore` and Stage 5 `currentRiskScore`.
- Sidebar navigation for Operations, Investigations, Feedback Model, and Reports views.

## What This Dashboard Shows

- Stage 4 fusion score.
- Stage 5 current score.
- Feedback adjustment.
- Signature evidence.
- ML prediction.
- Fusion decision and evidence.
- Analyst review flag.
- Guardrail and feedback reason.
- Model confidence is displayed as an XGBoost confidence score. It is not a calibrated probability and should not be interpreted as absolute certainty. Values very close to 1.0 are displayed as 99.9%+ to avoid implying guaranteed correctness.

## Stage 6B: Simulated Replay and Interactive Feedback

Stage 6B adds an offline replay mode and UI-only analyst feedback controls. Alerts are replayed from the static Stage 5 JSON output to simulate an operational triage queue. Analyst feedback changes the dashboard's local state and recalculates risk scores for demonstration purposes only.

This does not write back to the Stage 5 JSON files, does not retrain the model, and does not perform live packet capture.

Replay controls:

- Start, pause, resume, and reset replay.
- Replay speed options: 1x, 2x, and 5x.
- Show all alerts.
- Replay mode can be toggled on or off.

Feedback controls:

- Confirm Threat.
- Mark False Positive.
- Expected Activity.
- Needs Investigation.
- Escalate.
- Reset Feedback.

Local-only score adjustment uses front-end guardrails. Scores stay between 0 and 100, Critical alerts are not reduced below 70, Infiltration alerts are not reduced below 75, and signature/ML disagreement remains review-required.

Reset Replay clears local feedback overrides for the current browser session. No feedback is persisted.

## What Is Not Included Yet

- No live backend.
- No database.
- No real analyst write-back.
- No authentication.
- No live traffic.
- No model retraining.
- No live replay from network traffic.
- No backend persistence for Stage 6B feedback.

## Limitations

- Static JSON dashboard.
- Simulated feedback.
- Prototype evaluation.
- Layout inspired by a static SOC HTML prototype, but data still comes from Stage 4 and Stage 5 JSON outputs.
- Not production IDS.
