"""Stage 3 XGBoost IDS training scaffold.

This module prepares the future supervised ML training pipeline for the
Human-in-the-Loop IDS Dashboard. It should train on observable flow features and
labels, but it must not use dashboard-derived answer fields as model features.

The full training implementation depends on the local or Colab location of the
larger CSE-CIC-IDS2018 CSV files, so this file currently provides a safe
scaffold rather than a final model training pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGE_1_PROCESSED_DIR = REPO_ROOT / "stage-1" / "data" / "processed"
FEATURE_SAMPLE_PATH = STAGE_1_PROCESSED_DIR / "flow-feature-sample.csv"
GROUND_TRUTH_PATH = STAGE_1_PROCESSED_DIR / "ground-truth.json"
MODEL_DIR = REPO_ROOT / "stage-3" / "models"
EVALUATION_DIR = REPO_ROOT / "stage-3" / "evaluation"

MODEL_PATH = MODEL_DIR / "xgboost_ids_model.json"
FEATURE_COLUMNS_PATH = MODEL_DIR / "feature-columns.json"
LABEL_MAPPING_PATH = MODEL_DIR / "label-mapping.json"
PREPROCESSING_CONFIG_PATH = MODEL_DIR / "preprocessing-config.json"

LABEL_MAPPING = {
    "Benign": "Benign",
    "FTP-BruteForce": "Brute Force",
    "SSH-Bruteforce": "Brute Force",
    "Bot": "Botnet",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",
    "Infilteration": "Infiltration",
    "Infiltration": "Infiltration",
}

FORBIDDEN_FEATURE_FIELDS = {
    "Label",
    "rawLabel",
    "attackType",
    "mappedAttackType",
    "groundTruth",
    "severity",
    "similarityKey",
}


def require_optional_dependencies():
    """Import optional ML dependencies with a helpful scaffold message."""
    try:
        import pandas as pd  # type: ignore
        from sklearn.model_selection import train_test_split  # type: ignore
        from sklearn.metrics import classification_report  # type: ignore
        from xgboost import XGBClassifier  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "Stage 3 training dependencies are not installed yet. "
            "Install pandas, scikit-learn, and xgboost in a project environment "
            "before running the full training pipeline."
        ) from exc

    return pd, train_test_split, classification_report, XGBClassifier


def load_training_data(feature_path: Path = FEATURE_SAMPLE_PATH, ground_truth_path: Path = GROUND_TRUTH_PATH):
    """Load feature-only records and supervised labels for future training."""
    pd, *_ = require_optional_dependencies()

    if not feature_path.exists():
        raise FileNotFoundError(f"Feature input not found: {feature_path}")
    if not ground_truth_path.exists():
        raise FileNotFoundError(f"Ground truth labels not found: {ground_truth_path}")

    features = pd.read_csv(feature_path)
    with ground_truth_path.open("r", encoding="utf-8") as file:
        ground_truth = json.load(file)

    labels = features["id"].map(lambda alert_id: ground_truth.get(alert_id, {}).get("mappedAttackType"))
    return features, labels


def clean_flow_dataframe(dataframe):
    """Clean feature dataframe before training.

    TODO: Extend this when using larger raw CSE-CIC-IDS2018 exports. Typical
    cleaning should handle missing values, infinities, mixed dtypes, and
    dataset-specific column inconsistencies.
    """
    return dataframe.replace([float("inf"), float("-inf")], None).dropna()


def map_attack_labels(labels: Iterable[str]) -> list[str]:
    """Map raw CSE-CIC-IDS2018 labels into dashboard attack types."""
    return [LABEL_MAPPING.get(str(label), str(label)) for label in labels]


def select_feature_columns(dataframe) -> list[str]:
    """Select model feature columns while blocking answer-derived fields."""
    candidate_columns = [column for column in dataframe.columns if column != "id"]
    forbidden_used = sorted(FORBIDDEN_FEATURE_FIELDS.intersection(candidate_columns))
    if forbidden_used:
        raise ValueError(f"Forbidden answer fields cannot be used as ML features: {forbidden_used}")

    return candidate_columns


def train_model(features, labels):
    """Train the future XGBoost model.

    TODO: Implement train/test split, feature encoding, class mapping, and model
    fitting when Stage 3 moves beyond scaffold setup.
    """
    _, _, _, XGBClassifier = require_optional_dependencies()
    raise NotImplementedError("Stage 3 final XGBoost training is not implemented yet.")


def evaluate_model(model, test_features, test_labels):
    """Evaluate the future trained model.

    TODO: Add accuracy, precision, recall, F1, confusion matrix, false positives,
    false negatives, and per-class performance outputs.
    """
    raise NotImplementedError("Stage 3 model evaluation is not implemented yet.")


def save_artifacts(model, feature_columns: list[str], label_mapping: dict[str, str]):
    """Save future model and metadata artifacts."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

    FEATURE_COLUMNS_PATH.write_text(json.dumps(feature_columns, indent=2) + "\n", encoding="utf-8")
    LABEL_MAPPING_PATH.write_text(json.dumps(label_mapping, indent=2) + "\n", encoding="utf-8")
    PREPROCESSING_CONFIG_PATH.write_text(
        json.dumps({"forbiddenFeatureFields": sorted(FORBIDDEN_FEATURE_FIELDS)}, indent=2) + "\n",
        encoding="utf-8",
    )

    # TODO: Save the trained XGBoost model to MODEL_PATH after training exists.
    _ = model


def main() -> None:
    print("Stage 3 XGBoost IDS training scaffold.")
    print("No final model is trained by this scaffold yet.")
    print(f"Expected feature input: {FEATURE_SAMPLE_PATH}")
    print(f"Expected ground truth labels for supervised training/evaluation: {GROUND_TRUTH_PATH}")
    print("Prediction code must not use ground truth or dashboard-derived answer fields.")


if __name__ == "__main__":
    main()

