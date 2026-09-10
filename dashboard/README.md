# React IDS Dashboard

## Purpose

This React, Vite, and TypeScript application is the analyst-facing dashboard for the Human-in-the-Loop IDS project. It visualises static pipeline evidence and supports offline replay and browser-session feedback previews. It has no backend, database, authentication, live capture, or model retraining.

## Versioned Data

The application consumes four separate versioned artifacts:

```txt
dashboard/src/data/analyst-alerts.v1.json
dashboard/src/data/evaluator-summary.v1.json
dashboard/src/data/adaptation-demo-scenarios.v1.json
dashboard/src/data/dashboard-data-manifest.v1.json
```

The formal analyst artifact contains 995 held-out records. In the current dataset, 204 have at least one similarity match, but none pass every eligibility gate, so it honestly reports zero historical adaptations. Successful adaptation behaviour is shown only in the separately labelled demonstration-scenario artifact, generated through the real Stage 5 core.

See [ANALYST_DATA_CONTRACT.md](ANALYST_DATA_CONTRACT.md) for field definitions, score semantics, runtime validation, privacy checks, and analyst/evaluator boundaries.

## Important Boundaries

- Formal evaluation is not demonstration data.
- Analyst records are not evaluator records and contain no per-alert ground truth.
- Detection Score is the immutable automated score; Operational Priority is the Stage 5 ranking score.
- Model confidence is an uncalibrated XGBoost softprob value, not threat risk or certainty.
- TreeSHAP explains the predicted-class raw model margin; it does not contribute risk points.
- Browser session feedback preview is not persisted historical adaptation.

The formal evaluator summary can be displayed in Reports, but it remains a distinct aggregate-only artifact. Ground truth is never copied into operational alert records or used for adaptation.

## Run Locally

```powershell
cd dashboard
npm ci
npm run dev
```

Production build:

```powershell
npm run build
```

## Reproduce Dashboard Data

Run Stage 3 local inference first to produce the ignored full-schema prediction artifact. Then use temporary Stage 4 and Stage 5 directories so committed pipeline samples are not overwritten:

```powershell
node stage-4/scripts/run-fusion-demo.js --ml-predictions stage-3/outputs/ml-predictions.regenerated.json --output-dir .tmp-stage-3-artifacts/stage5b/stage4/outputs --evaluation-dir .tmp-stage-3-artifacts/stage5b/stage4/evaluation
node stage-5/scripts/run-feedback-demo.js --fused-alerts .tmp-stage-3-artifacts/stage5b/stage4/outputs/fusion-alerts.sample.json --output-dir .tmp-stage-3-artifacts/stage5b/stage5/outputs --evaluation-dir .tmp-stage-3-artifacts/stage5b/stage5/evaluation
node dashboard/scripts/generate-adaptation-demo-scenarios.mjs
node dashboard/scripts/export-dashboard-data.mjs --analyst-input .tmp-stage-3-artifacts/stage5b/stage5/outputs/feedback-adjusted-alerts.sample.json --feedback-summary .tmp-stage-3-artifacts/stage5b/stage5/evaluation/feedback-evaluation-summary.json --fusion-summary .tmp-stage-3-artifacts/stage5b/stage4/evaluation/fusion-evaluation-summary.json --demo-scenarios dashboard/src/data/adaptation-demo-scenarios.v1.json
```

The exporter transforms and validates Stage 5 output only. It does not recalculate ML predictions, SHAP, fusion, similarity, feedback aggregation, guardrails, or priority.

Run the integration tests with:

```powershell
npm run test:data
```

## GitHub Pages

Public URL:

```txt
https://lck0629.github.io/ids-dashboard/
```

Deployment is rebuilt from `main` using GitHub Actions. Local development continues to use `npm run dev`. The published site contains static, offline research data only and does not imply production IDS operation.

## Current UI Scope

The existing interface includes Operations, Investigations, Feedback Model, and Reports views; priority-sorted alert triage; attack-type filters; signature evidence; ML prediction evidence; feedback/guardrail context; and replay controls. The canonical artifact now carries TreeSHAP evidence, but a dedicated SHAP visualisation is intentionally deferred.

The local feedback scorer remains isolated as a session preview for the existing prototype interaction. It never overwrites `detectionScore`, is not written back, and is not the authority for the initial queue ordering.
