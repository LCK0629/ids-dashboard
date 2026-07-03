# Stage 5 Feedback Evaluation Summary

Stage 5 applies simulated analyst feedback and JSON-based exception memory to Stage 4 fused alerts.

Ground truth is joined only after feedback adjustment for evaluation. This is a prototype workload and priority evaluation, not production IDS performance.

## Overall Counts

- Total alerts: 1000
- Alerts adjusted: 362
- Alerts unchanged: 638
- Direct feedback applied count: 5
- Unmatched direct feedback count: 1
- Exception memory applied count: 359
- Ignored exception count: 119
- Guardrail applied count: 219
- Score adjustment guardrail count: 100
- Exception rejected by trust gate count: 119
- Low confidence exception ignored count: 24
- Insufficient feedback exception ignored count: 95

## Guardrail Metric Clarification

`guardrailAppliedCount` is a broad combined count. It includes both score-limiting guardrails and exception trust-gate rejections.

`scoreAdjustmentGuardrailCount` counts cases where a risk score adjustment was actually limited by a safety rule, such as maximum reduction, Critical alert floor, or Infiltration floor.

`exceptionRejectedByTrustGateCount` counts exception memory matches that were ignored because they did not meet trust requirements. This includes low confidence exceptions and exceptions with insufficient feedback evidence.

Trust-gate rejections do not change the risk score. For report writing, use the split metrics when describing whether feedback changed priority or whether an exception was rejected before adjustment.

## Risk Before And After Feedback

- Average risk before feedback: 48.57
- Average risk after feedback: 42.26
- Average risk change: -6.31
- High-risk threshold: 70
- High-risk alerts before: 424
- High-risk alerts after: 399

## Review Queue Before And After Feedback

- Review queue before: 456
- Review queue after: 401
- Reviewed benign before: 87
- Reviewed benign after: 42
- Reviewed malicious before: 369
- Reviewed malicious after: 359

## Ground Truth Evaluation

- Evaluated with ground truth count: 1000
- Benign high-risk before: 65
- Benign high-risk after: 40
- Malicious high-risk before: 359
- Malicious high-risk after: 359
- True positive suppression count: 0
- Infiltration adjusted count: 0
- Infiltration guardrail count: 0

## Count By Analyst Feedback Status

- unchanged: 517
- adjusted_by_exception_memory: 260
- guardrail_limited_adjustment: 100
- ignored_insufficient_feedback: 95
- ignored_low_confidence_exception: 24
- confirmed_true_positive: 1
- marked_expected_activity: 1
- needs_investigation: 1
- escalated: 1

## Notes

- Ground truth is joined only after feedback adjustment for evaluation.
- This is a prototype feedback evaluation, not production IDS performance.
- The goal is to show workload and priority changes after simulated analyst feedback.
