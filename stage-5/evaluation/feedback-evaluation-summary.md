# Stage 5 Feedback Evaluation Summary

Stage 5 applies append-only analyst feedback events to Stage 4 fused alerts through deterministic similarity matching, historical aggregation, eligibility gates, and guardrails.

Ground truth is joined only after detection, fusion, and feedback for evaluation and dashboard explanation. It is not used as input to signature matching, ML prediction, fusion scoring, or feedback adjustment.

This is a prototype workload and priority evaluation, not production IDS performance.

## Overall Counts

- Total alerts: 1000
- Manual exception memory enabled: false
- Alerts adjusted: 4
- Alerts unchanged: 996
- Direct feedback applied count: 5
- Unmatched direct feedback count: 1
- Historical feedback adaptation count: 0
- Exception memory applied count: 0
- Ignored exception count: 0
- Guardrail applied count: 1
- Score adjustment guardrail count: 1
- Exception rejected by trust gate count: 0
- Low confidence exception ignored count: 0
- Insufficient feedback exception ignored count: 0

## Guardrail Metric Clarification

`guardrailAppliedCount` is a broad combined count. It includes both score-limiting guardrails and exception trust-gate rejections.

`scoreAdjustmentGuardrailCount` counts cases where a risk score adjustment was actually limited by a safety rule, such as maximum reduction, Critical alert floor, or Infiltration floor.

`exceptionRejectedByTrustGateCount` counts exception memory matches that were ignored because they did not meet trust requirements. This includes low confidence exceptions and exceptions with insufficient feedback evidence.

Trust-gate rejections do not change the risk score. For report writing, use the split metrics when describing whether feedback changed priority or whether an exception was rejected before adjustment.

## Adaptation Coverage

- Similarity match count: 204
- Similarity match coverage: 0.204
- Adaptation eligible count: 0
- Adaptation eligibility coverage: 0
- Actual adaptation count: 0
- Actual adaptation coverage: 0
- Generated historical memory count: 3

## Risk Before And After Feedback

- Average risk before feedback: 43.56
- Average risk after feedback: 43.55
- Average risk change: -0.01
- High-risk threshold: 70
- High-risk alerts before: 424
- High-risk alerts after: 424

## Review Queue Before And After Feedback

- Review queue before: 424
- Review queue after: 426
- Reviewed benign before: 65
- Reviewed benign after: 67
- Reviewed malicious before: 359
- Reviewed malicious after: 359

## Ground Truth Evaluation

- Evaluated with ground truth count: 1000
- Benign high-risk before: 65
- Benign high-risk after: 65
- Malicious high-risk before: 359
- Malicious high-risk after: 359
- True positive suppression count: 0
- Infiltration adjusted count: 0
- Infiltration guardrail count: 0

## Count By Analyst Feedback Status

- unchanged: 995
- confirmed_true_positive: 1
- marked_expected_activity: 1
- guardrail_limited_adjustment: 1
- escalated: 1
- needs_investigation: 1

## Count By Adaptation Source

- none: 995
- direct_feedback: 5

## Notes

- Analyst feedback events are the source of truth. Generated historical feedback memory is derived data and should not be manually authored.
- Ground truth is joined only after detection, fusion, feedback aggregation, and priority adaptation for evaluation and dashboard explanation. It is not used as adaptation input.
- Detection score is preserved as detectionScore/fusionRiskScore. Historical feedback affects operationalPriorityScore for ranking.
- Manual exception memory is disabled for formal adaptive evaluation so improvements can be attributed to analyst feedback events.
- This is a prototype feedback evaluation, not production IDS performance.
