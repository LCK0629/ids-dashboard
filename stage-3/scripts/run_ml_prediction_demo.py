"""Stage 3 ML prediction demo scaffold.

The future prediction script must load feature-only input, load saved model
artifacts, produce ML predictions, and only then join ground truth for
evaluation. It must not use labels to create predictions.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FEATURE_INPUT_PATH = REPO_ROOT / "stage-1" / "data" / "processed" / "flow-feature-sample.csv"
GROUND_TRUTH_PATH = REPO_ROOT / "stage-1" / "data" / "processed" / "ground-truth.json"
MODEL_DIR = REPO_ROOT / "stage-3" / "models"
OUTPUT_DIR = REPO_ROOT / "stage-3" / "outputs"
EVALUATION_DIR = REPO_ROOT / "stage-3" / "evaluation"

MODEL_PATH = MODEL_DIR / "xgboost_ids_model.json"
FEATURE_COLUMNS_PATH = MODEL_DIR / "feature-columns.json"
LABEL_MAPPING_PATH = MODEL_DIR / "label-mapping.json"
PREDICTION_OUTPUT_PATH = OUTPUT_DIR / "ml-predictions.sample.json"

FORBIDDEN_PREDICTION_FIELDS = {
    "Label",
    "rawLabel",
    "attackType",
    "mappedAttackType",
    "groundTruth",
    "severity",
    "similarityKey",
}


def model_artifacts_available() -> bool:
    """Return whether all required future model artifacts are available."""
    return MODEL_PATH.exists() and FEATURE_COLUMNS_PATH.exists() and LABEL_MAPPING_PATH.exists()


def load_feature_only_input():
    """Load feature-only prediction input.

    TODO: Load with pandas once prediction is implemented. This function should
    validate that forbidden answer fields are absent before model inference.
    """
    if not FEATURE_INPUT_PATH.exists():
        raise FileNotFoundError(f"Feature-only input not found: {FEATURE_INPUT_PATH}")

    return FEATURE_INPUT_PATH


def load_model_artifacts():
    """Load future model artifacts from stage-3/models/."""
    if not model_artifacts_available():
        print("Stage 3 model artifacts are not available yet. Run training first.")
        return None

    return {
        "modelPath": MODEL_PATH,
        "featureColumns": json.loads(FEATURE_COLUMNS_PATH.read_text(encoding="utf-8")),
        "labelMapping": json.loads(LABEL_MAPPING_PATH.read_text(encoding="utf-8")),
    }


def produce_predictions(feature_input, artifacts):
    """Produce future ML predictions without reading ground truth.

    TODO: Implement XGBoost inference after training artifacts exist.
    Do not generate random or label-derived predictions.
    """
    _ = feature_input
    _ = artifacts
    raise NotImplementedError("Stage 3 ML prediction is not implemented until model artifacts exist.")


def write_predictions(predictions) -> None:
    """Write future ML predictions to stage-3/outputs/."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PREDICTION_OUTPUT_PATH.write_text(json.dumps(predictions, indent=2) + "\n", encoding="utf-8")


def evaluate_predictions_after_prediction(predictions) -> None:
    """Join ground truth only after prediction for future evaluation."""
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    if not GROUND_TRUTH_PATH.exists():
        print(f"Ground truth file not found for evaluation: {GROUND_TRUTH_PATH}")
        return

    # TODO: Compute accuracy, precision, recall, F1, confusion matrix, false
    # positives, false negatives, and per-class performance.
    _ = predictions


def main() -> None:
    print("Stage 3 ML prediction scaffold.")
    feature_input = load_feature_only_input()
    artifacts = load_model_artifacts()

    if artifacts is None:
        print(f"Feature-only input is ready: {feature_input}")
        print("No predictions were generated.")
        return

    predictions = produce_predictions(feature_input, artifacts)
    write_predictions(predictions)
    evaluate_predictions_after_prediction(predictions)


if __name__ == "__main__":
    main()

