# Stage 4 Fusion Alignment

## Problem Background

Stage 4 combines Stage 2 signature evidence with Stage 3 ML predictions. This only works correctly when both stages refer to the same alert IDs.

Earlier Stage 3 outputs included held-out test predictions from the model training split. Those predictions were useful for Stage 3 evaluation, but they did not use the same `AL-XXXX` IDs as the Stage 1 / Stage 2 sample. Adding those rows directly to Stage 4 made the fused output look larger than the real dashboard alert queue.

## Stage-2-Scoped Fusion Mode

Stage 4 now uses Stage-2-scoped fusion mode.

The fused alert queue is based on Stage 2 records, which are generated from the Stage 1 sample. Stage 3 predictions are joined only when their IDs match Stage 2 IDs.

This keeps the dashboard fusion output tied to the same alert set instead of mixing in unrelated ML evaluation rows.

## Why ID Alignment Matters

The Fusion Engine is not only a classifier. It is a prioritisation and review-decision layer for alerts that should appear in the dashboard.

If Stage 2 and Stage 3 IDs do not align, Stage 4 cannot fairly combine their evidence. A low overlap rate may mean that ML predictions were generated from a different dataset split, a different sample, or a file with incompatible IDs.

## Alignment Metrics

Stage 4 records an `idAlignmentSummary` in `stage-4/evaluation/fusion-evaluation-summary.json`.

The summary includes:

- Stage 2 record count.
- Stage 3 prediction count.
- Matched ID count.
- Stage 2-only count.
- Stage 3 out-of-scope count.
- Overlap rate against Stage 2.
- Overlap rate against Stage 3.
- Alignment status.
- Alignment warning.
- Sample Stage 2-only IDs.
- Sample out-of-scope Stage 3 prediction IDs.

The current status thresholds are:

- `OK`: Stage 2 overlap is at least 95%.
- `WARNING_PARTIAL_OVERLAP`: Stage 2 overlap is at least 50% but below 95%.
- `ERROR_LOW_OVERLAP`: Stage 2 overlap is below 50%.

Low overlap does not crash the script. It is reported clearly so the data source problem can be fixed.

## Out-of-Scope ML Predictions

Out-of-scope Stage 3 predictions are ML predictions whose IDs are not present in Stage 2.

They are not inserted into the dashboard fusion queue. They are reported for debugging because they may indicate that the wrong Stage 3 prediction file was used.

Held-out ML predictions remain useful for Stage 3 model evaluation, but they should not be silently mixed into Stage 4 dashboard fusion.

## Current Expected Result

With the current aligned Stage 3 sample:

- Stage 4 fused output remains scoped to 1000 Stage 2 records.
- Stage 3 predictions are joined only for matching `AL-XXXX` IDs.
- Stage 2-only IDs are reported when an alert has no paired ML evidence.
- Stage 3 out-of-scope predictions are reported but excluded from the fused dashboard queue.

## Limitations

This is still a prototype evaluation.

The ID alignment report checks whether records can be joined safely, but it does not prove production IDS performance. Ground truth is joined only after fusion for evaluation metrics.

`ML_ONLY_NO_SIGNATURE_RECORD` remains in the single-alert `fuseAlert()` primitive for direct callers and possible future union-mode fusion. In the current Stage-2-scoped batch workflow, it is not normally emitted because `fuseAlerts()` iterates over Stage 2 IDs only.
