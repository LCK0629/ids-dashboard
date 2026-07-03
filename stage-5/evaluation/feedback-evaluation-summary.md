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
