# Stage 4 Fusion Engine

## Purpose

Stage 4 combines Stage 2 signature evidence and Stage 3 XGBoost ML predictions into one hybrid IDS alert output.

The output gives each alert a fused attack decision, fused risk score, explanation, confidence level, and analyst review flag.

## Role in Hybrid IDS

Stage 4 sits between:

- Stage 2 Signature Detection.
- Stage 3 ML Detection.
- Stage 5 Human Feedback / Exception Memory.

Stage 2 is useful when a known flow pattern is detected. Stage 3 is useful when the ML model sees attack-like flow behavior. Stage 4 joins these two signals before later human feedback is added.

## Inputs

Stage 4 reads:

```txt
stage-2/data/signature-output.sample.json
stage-3/outputs/ml-predictions.sample.json
```

For evaluation only, it can also read:

```txt
stage-1/data/processed/ground-truth.json
```

Ground truth is not used when calculating fusion decisions or risk scores.

## Fusion Logic

The fusion engine handles these cases:

- Signature and ML agree.
- Signature hits but ML predicts a different attack type.
- Signature hits but ML predicts Benign.
- No signature hit but ML predicts a non-benign class with high confidence.
- No signature hit but ML predicts a non-benign class with medium confidence.
- No signature hit and ML predicts Benign.
- Signature record exists but no ML prediction exists.
- ML prediction exists but no signature record exists.

The script also handles IDs that appear only on one side. This matters because the current Stage 2 and Stage 3 sample outputs do not use exactly the same ID set.

## Risk Scoring

Signature severity is converted into a numeric score:

```txt
Low -> 40
Medium -> 60
High -> 80
Critical -> 95
```

ML `baseRiskScore` is used when available. If it is missing, the score is derived from model confidence.

All final scores are clamped between 0 and 100.

Fusion confidence level is based on the final score:

```txt
Critical: 90-100
High: 70-89
Medium: 40-69
Low: 0-39
```

## Infiltration ML Limitation Handling

The current Stage 3 ML model does not support `Infiltration`. The current ML artifacts are a six-class prototype.

Because Stage 2 still has an Infiltration signature rule, Stage 4 keeps Infiltration signature alerts instead of downgrading them due to missing ML support.

When Stage 2 indicates `Infiltration`, Stage 4 uses:

```txt
fusionDecision = SIGNATURE_ONLY_ML_LIMITATION
fusionAttackType = Infiltration
requiresAnalystReview = true
```

This keeps the limitation visible and avoids pretending that the ML model can classify Infiltration.

## Outputs

Stage 4 writes:

```txt
stage-4/outputs/fusion-alerts.sample.json
stage-4/evaluation/fusion-evaluation-summary.json
stage-4/evaluation/fusion-evaluation-summary.md
```

The fused alert output is sorted by risk score, analyst review flag, and ID so it is easier to use in a later dashboard.

## Evaluation

Evaluation joins ground truth only after fusion is completed.

The summary includes decision counts, confidence counts, analyst review count, risk score statistics, attack type counts, signature/ML agreement counts, and simple ground-truth comparison where labels are available.

This is a Stage 4 prototype evaluation. It should not be treated as final production IDS accuracy.

## How to Run

From the repository root:

```powershell
node stage-4/scripts/run-fusion-demo.js
```

## What Is Not Included Yet

- No human feedback adaptation.
- No Exception Memory.
- No dashboard integration.
- No backend API.
- No model retraining.
- No production deployment.

## Limitations

- Fusion scoring is rule-based and interpretable.
- Current weights and score adjustments are prototype values.
- Stage 3 currently excludes Infiltration.
- Future validation is still needed.
- Stage 5 will later adjust risk using human feedback.

