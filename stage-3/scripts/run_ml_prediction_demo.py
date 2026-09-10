"""Run reproducible local Stage 3 XGBoost inference.

This script loads committed model artifacts and feature-only flow records,
validates the exact 78-feature schema, writes prediction evidence, and can
compare regenerated predictions with the committed Stage 3 sample output.

It does not read ground truth and it does not train or overwrite the model.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "stage-3" / "core"))

from ml_inference import (  # noqa: E402
    DEFAULT_FEATURE_INPUT_PATH,
    load_model_artifacts,
    predict_csv,
    write_predictions,
)

OUTPUT_DIR = REPO_ROOT / "stage-3" / "outputs"
DEFAULT_OUTPUT_PATH = OUTPUT_DIR / "ml-predictions.regenerated.json"
COMMITTED_OUTPUT_PATH = OUTPUT_DIR / "ml-predictions.sample.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def index_by_id(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(record.get("id")): record for record in records}


def compare_predictions(regenerated: list[dict[str, Any]], committed_path: Path = COMMITTED_OUTPUT_PATH) -> dict[str, Any] | None:
    if not committed_path.exists():
        return None

    committed = load_json(committed_path)
    regenerated_by_id = index_by_id(regenerated)
    committed_by_id = index_by_id(committed)
    shared_ids = sorted(set(regenerated_by_id) & set(committed_by_id))
    agreement_count = 0
    confidence_differences: list[float] = []
    mismatch_examples: list[dict[str, Any]] = []

    for alert_id in shared_ids:
        new_record = regenerated_by_id[alert_id]
        old_record = committed_by_id[alert_id]
        if new_record.get("predictionStatus") != "available":
            continue
        if new_record.get("predictedAttackType") == old_record.get("predictedAttackType"):
            agreement_count += 1
        elif len(mismatch_examples) < 10:
            mismatch_examples.append({
                "id": alert_id,
                "committedPredictedAttackType": old_record.get("predictedAttackType"),
                "regeneratedPredictedAttackType": new_record.get("predictedAttackType"),
                "committedConfidence": old_record.get("modelConfidence"),
                "regeneratedConfidence": new_record.get("modelConfidence"),
            })

        old_confidence = old_record.get("modelConfidence")
        new_confidence = new_record.get("modelConfidence")
        if old_confidence is not None and new_confidence is not None:
            confidence_differences.append(abs(float(new_confidence) - float(old_confidence)))

    unavailable_count = sum(1 for record in regenerated if record.get("predictionStatus") != "available")
    confidence_stats = {
        "count": len(confidence_differences),
        "max": max(confidence_differences) if confidence_differences else None,
        "mean": statistics.fmean(confidence_differences) if confidence_differences else None,
        "median": statistics.median(confidence_differences) if confidence_differences else None,
    }

    return {
        "regeneratedRows": len(regenerated),
        "committedRows": len(committed),
        "sharedRows": len(shared_ids),
        "availableRows": sum(1 for record in regenerated if record.get("predictionStatus") == "available"),
        "unavailableRows": unavailable_count,
        "predictedClassAgreementCount": agreement_count,
        "predictedClassAgreementRate": round(agreement_count / len(shared_ids), 6) if shared_ids else 0,
        "confidenceDifferenceStats": confidence_stats,
        "mismatchExamples": mismatch_examples,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Stage 3 local XGBoost inference.")
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_FEATURE_INPUT_PATH,
        help="Feature-only CSV input. Defaults to stage-1/data/processed/flow-feature-full.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Prediction JSON output. Defaults to stage-3/outputs/ml-predictions.regenerated.json.",
    )
    parser.add_argument(
        "--compare-with",
        type=Path,
        default=COMMITTED_OUTPUT_PATH,
        help="Optional committed prediction output to compare against.",
    )
    parser.add_argument(
        "--overwrite-sample",
        action="store_true",
        help="Explicitly write to stage-3/outputs/ml-predictions.sample.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = COMMITTED_OUTPUT_PATH if args.overwrite_sample else args.output
    artifacts = load_model_artifacts()
    predictions = predict_csv(args.input, artifacts)
    write_predictions(predictions, output_path)
    comparison = compare_predictions(predictions, args.compare_with)

    available_count = sum(1 for record in predictions if record.get("predictionStatus") == "available")
    unavailable_count = len(predictions) - available_count
    print(f"Input: {args.input}")
    print(f"Predictions written: {output_path}")
    print(f"Total rows: {len(predictions)}")
    print(f"Available predictions: {available_count}")
    print(f"Unavailable predictions: {unavailable_count}")
    print(f"ML classes: {list(artifacts.label_mapping.values())}")
    print("Infiltration supported by ML:", "Infiltration" in set(artifacts.label_mapping.values()))
    print("Model provenance:")
    for key, value in artifacts.provenance.items():
        print(f"- {key}: {value}")

    if comparison is not None:
        print("Prediction comparison:")
        print(json.dumps(comparison, indent=2))
    else:
        print("Prediction comparison: committed output not found.")


if __name__ == "__main__":
    main()

