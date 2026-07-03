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

## Stage-2-Scoped Fusion Mode

Stage 4 currently uses Stage-2-scoped fusion mode. The fused dashboard alert queue is based on Stage 2 / Stage 1 alert IDs.

Stage 3 predictions are joined only when their IDs match Stage 2 records. Unmatched Stage 3 predictions are treated as out of scope for dashboard fusion and are reported for debugging instead of being silently inserted into fused alerts.

Held-out ML predictions are still useful for Stage 3 model evaluation, but they should not be mixed into Stage 4 dashboard fusion unless they refer to the same `AL-XXXX` alert IDs.

## Fusion Logic

The fusion engine handles these cases:

- Signature and ML agree.
- Signature hits but ML predicts a different attack type.
- Signature hits but ML predicts Benign.
- No signature hit but ML predicts a non-benign class with high confidence.
- No signature hit but ML predicts a non-benign class with medium confidence.
- No signature hit and ML predicts Benign.
- Signature record exists but no ML prediction exists.
- ML prediction exists but no signature record exists, which is reported as out of scope instead of being added to the fused dashboard output.

The fused dashboard output is scoped to Stage 2 signature records. Stage 3 predictions are joined only when their IDs match those records. This prevents held-out ML evaluation predictions from inflating the Stage 4 dashboard output.

`ML_ONLY_NO_SIGNATURE_RECORD` is retained for direct `fuseAlert()` callers and any future union-mode fusion. In the current Stage-2-scoped dashboard fusion workflow, this case is not normally emitted because fusion iterates over Stage 2 IDs only.

## Risk Scoring

Signature severity is converted into a numeric score:

```txt
Low -> 40
Medium -> 60
High -> 80
Critical -> 95
```

ML `baseRiskScore` is used when available. If it is missing, the score is derived from model confidence.

ML-only high-confidence alerts remain high priority, but they are slightly discounted because no signature evidence supports the prediction. This keeps Signature + ML agreement as the strongest evidence case.

ML-only medium-confidence alerts receive a stronger discount because both signature support and high ML confidence are absent.

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

The summary includes:

- ID alignment metrics: Stage 2 record count, Stage 3 prediction count, matched ID count, Stage 2-only count, Stage 3 out-of-scope count, overlap rates, alignment status, warnings, and capped ID samples.
- Classification metrics: accuracy, macro F1, weighted F1, binary TP/TN/FP/FN, per-class precision / recall / F1, and a confusion matrix.
- Fusion behaviour metrics: decision counts, confidence counts, attack type counts, signature/ML agreement and disagreement counts, ML-only count, signature-only count, and Infiltration ML limitation count.
- Risk prioritisation metrics: benign/malicious average risk score, top-k precision, high-risk threshold precision, high-risk benign count, and low-risk malicious count.
- Analyst review metrics: review count, review rate, reviewed malicious/benign counts, review precision, malicious records not requiring review, and benign records requiring review.

The older simple fusion accuracy is kept as a quick readable indicator, but it is not enough by itself because Stage 4 is also a prioritisation and review-decision layer.

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
