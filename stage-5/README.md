# Stage 5 Human Feedback and Exception Memory

## Purpose

Stage 5 applies append-only analyst feedback history to Stage 4 fused alerts through deterministic similarity, aggregation, eligibility, and guardrail logic. Manual exception memory remains available only for backwards-compatible demonstrations and is disabled in formal held-out evaluation.

It preserves the original Stage 4 Detection Score and produces a separate Operational Priority for ranking. Legacy field aliases remain in output for compatibility.

## Role in Human-in-the-Loop IDS

Stage 5 is the first formal Human-in-the-Loop layer in the project.

Stage 2 and Stage 3 produce automated detection evidence. Stage 4 fuses those signals into alert priorities. Stage 5 shows how analyst decisions can influence future priority without overwriting the original machine-generated score.

## Inputs

Stage 5 reads:

```txt
stage-4/outputs/fusion-alerts.sample.json
stage-5/data/analyst-feedback.sample.json
stage-5/data/exception-memory.sample.json
```

For evaluation only, it can also read:

```txt
stage-1/data/processed/ground-truth.json
```

Ground truth is not used to decide feedback adjustments.

## Feedback Types

Supported simulated analyst feedback types:

- `confirm_true_positive`: analyst confirms a real attack.
- `mark_false_positive`: analyst marks an alert as benign or false alarm.
- `mark_expected_activity`: analyst marks the activity as approved or expected.
- `needs_investigation`: analyst keeps the alert under review.
- `escalate`: analyst raises the alert priority.

## Exception Memory

Exception memory stores repeated feedback-derived patterns, such as expected activity or repeated false positives.

Each exception memory record contains a simple `matchFields` object. An alert must match all listed fields before the exception can be considered.

Exception memory only applies when:

- the exception is enabled,
- all required fields match,
- `feedbackCount >= 3`,
- `confidence >= 0.6`.

## Feedback Adjustment Logic

Direct analyst feedback is applied first.

Exception memory is applied only if there is no direct feedback for that alert. If direct feedback and exception memory both match, the exception is recorded but not applied because direct analyst feedback takes priority.

The original `fusionRiskScore` is preserved. Stage 5 adds:

```txt
currentRiskScore
```

## Guardrails

Stage 5 uses guardrails so feedback does not suppress serious alerts too aggressively.

- Maximum reduction: risk cannot be reduced by more than 30 points.
- Critical floor: Critical alerts are not reduced below 70.
- Infiltration floor: Infiltration alerts are not reduced below 75.
- Low confidence exceptions are ignored.
- Exceptions with fewer than 3 feedback records are ignored.

## Outputs

Stage 5 writes:

```txt
stage-5/outputs/feedback-adjusted-alerts.sample.json
stage-5/evaluation/feedback-evaluation-summary.json
stage-5/evaluation/feedback-evaluation-summary.md
```

The adjusted alert output is sorted by `currentRiskScore`, analyst review flag, and ID so it is ready for later dashboard integration.

## Evaluation

The evaluation summary compares before and after feedback:

- risk score averages,
- high-risk alert counts,
- review queue size,
- benign and malicious high-risk counts,
- reviewed benign and malicious counts,
- true positive suppression count,
- guardrail and exception memory counts.

The broad `guardrailAppliedCount` includes both score-limiting guardrails and exception trust-gate rejections. For report writing, use `scoreAdjustmentGuardrailCount` when referring only to cases where a score adjustment was capped or floored, and use `exceptionRejectedByTrustGateCount` for exceptions ignored due to low confidence or insufficient feedback.

Ground truth is joined only after feedback adjustment for evaluation.

## How to Run

From the repository root, use the committed defaults:

```powershell
node stage-5/scripts/run-feedback-demo.js
```

To consume a temporary full-schema Stage 4 artifact without overwriting committed Stage 5 outputs:

```powershell
node stage-5/scripts/run-feedback-demo.js --fused-alerts .tmp-stage-3-artifacts/stage5b/stage4/outputs/fusion-alerts.sample.json --output-dir .tmp-stage-3-artifacts/stage5b/stage5/outputs --evaluation-dir .tmp-stage-3-artifacts/stage5b/stage5/evaluation
```

The formal run uses a frozen calibration / held-out split. It does not claim chronological temporal evaluation. Ground truth is loaded only after held-out ranking and is written only to evaluator outputs.

The versioned React contract and transformation boundary are documented in `dashboard/ANALYST_DATA_CONTRACT.md`. The Stage 5 runner is the score authority; the dashboard exporter only validates and reshapes its analyst-safe output.

Run Stage 4 first if `stage-4/outputs/fusion-alerts.sample.json` does not exist.

## What Is Not Included Yet

- No persistent analyst write-back.
- No database.
- No model retraining.
- No online learning.
- No production deployment.

## Limitations

- Feedback is simulated.
- Exception memory is JSON-based.
- Matching logic is intentionally simple and explainable.
- Future work should use real analyst study data or dashboard interactions.
- This is a prototype feedback adaptation layer, not production IDS performance.
