# Stage 6 React Dashboard Integration

## Purpose

This dashboard visualises Stage 5 feedback-adjusted IDS alerts.

It is the formal React dashboard integration layer for the staged Human-in-the-Loop IDS project.

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

## What Is Not Included Yet

- No live backend.
- No database.
- No real analyst write-back.
- No authentication.
- No live traffic.
- No model retraining.

## Limitations

- Static JSON dashboard.
- Simulated feedback.
- Prototype evaluation.
- Not production IDS.
