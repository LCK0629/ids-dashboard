from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "stage-3" / "core"))
sys.path.insert(0, str(REPO_ROOT / "stage-3" / "scripts"))

from ml_inference import (  # noqa: E402
    DEFAULT_FEATURE_COLUMNS_PATH,
    DEFAULT_FEATURE_INPUT_PATH,
    DEFAULT_LABEL_MAPPING_PATH,
    DEFAULT_MODEL_PATH,
    DEFAULT_PREPROCESSING_CONFIG_PATH,
    load_json,
    load_model_artifacts,
    predict_dataframe,
    sha256_file,
)
from run_ml_prediction_demo import compare_predictions  # noqa: E402


def load_feature_rows(limit: int = 3) -> pd.DataFrame:
    return pd.read_csv(DEFAULT_FEATURE_INPUT_PATH, low_memory=False).head(limit)


def mutable_feature_rows(limit: int = 3) -> pd.DataFrame:
    return load_feature_rows(limit).astype(object)


def assert_available_prediction(record: dict) -> None:
    assert record["predictionStatus"] == "available"
    assert record["predictedClassIndex"] is not None
    assert record["predictedAttackType"]
    assert record["modelConfidence"] is not None
    assert record["classProbabilities"]


def test_committed_model_loads_successfully() -> None:
    artifacts = load_model_artifacts()

    assert artifacts.model.num_features() == 78
    assert artifacts.provenance["modelSha256"] == sha256_file(DEFAULT_MODEL_PATH)


def test_model_feature_count_is_78() -> None:
    artifacts = load_model_artifacts()

    assert len(artifacts.feature_columns) == 78


def test_feature_order_exactly_matches_feature_columns_json() -> None:
    artifacts = load_model_artifacts()
    feature_columns = load_json(DEFAULT_FEATURE_COLUMNS_PATH)

    assert artifacts.feature_columns == feature_columns


def test_input_columns_are_reordered_to_exact_feature_schema() -> None:
    artifacts = load_model_artifacts()
    dataframe = load_feature_rows(1)
    shuffled = dataframe[["id", *reversed(artifacts.feature_columns)]]
    predictions = predict_dataframe(shuffled, artifacts)

    assert_available_prediction(predictions[0])


def test_missing_feature_column_returns_unavailable_prediction() -> None:
    artifacts = load_model_artifacts()
    dataframe = load_feature_rows(1).drop(columns=[artifacts.feature_columns[0]])
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "unavailable"
    assert predictions[0]["failureReason"] == "missing_required_feature_columns"
    assert artifacts.feature_columns[0] in predictions[0]["missingFeatureColumns"]


def test_duplicate_feature_column_returns_safe_rejection() -> None:
    artifacts = load_model_artifacts()
    dataframe = load_feature_rows(1)
    duplicate_name = artifacts.feature_columns[0]
    dataframe = pd.concat([dataframe, dataframe[[duplicate_name]]], axis=1)
    dataframe.columns = list(dataframe.columns[:-1]) + [duplicate_name]
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "unavailable"
    assert predictions[0]["failureReason"] == "duplicate_feature_columns"
    assert duplicate_name in predictions[0]["duplicateFeatureColumns"]


def test_numeric_string_coercion_works() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(1)
    for column in artifacts.feature_columns:
        dataframe.loc[dataframe.index[0], column] = str(dataframe.loc[dataframe.index[0], column])
    predictions = predict_dataframe(dataframe, artifacts)

    assert_available_prediction(predictions[0])


def test_invalid_numeric_value_returns_unavailable_prediction() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(1)
    dataframe.loc[dataframe.index[0], artifacts.feature_columns[0]] = "not-a-number"
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "unavailable"
    assert predictions[0]["failureReason"] == "invalid_numeric_feature_values"
    assert artifacts.feature_columns[0] in predictions[0]["invalidFeatureColumns"]


def test_nan_returns_unavailable_prediction() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(1)
    dataframe.loc[dataframe.index[0], artifacts.feature_columns[0]] = np.nan
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "unavailable"
    assert predictions[0]["failureReason"] == "invalid_numeric_feature_values"


def test_positive_and_negative_infinity_return_unavailable_prediction() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(2)
    dataframe.loc[dataframe.index[0], artifacts.feature_columns[0]] = math.inf
    dataframe.loc[dataframe.index[1], artifacts.feature_columns[0]] = -math.inf
    predictions = predict_dataframe(dataframe, artifacts)

    assert [record["predictionStatus"] for record in predictions] == ["unavailable", "unavailable"]
    assert all(record["failureReason"] == "invalid_numeric_feature_values" for record in predictions)


def test_value_too_large_for_float32_returns_unavailable_prediction() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(1)
    dataframe.loc[dataframe.index[0], artifacts.feature_columns[0]] = float(np.finfo(np.float32).max) * 2
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "unavailable"
    assert predictions[0]["failureReason"] == "invalid_numeric_feature_values"


def test_one_bad_row_does_not_prevent_valid_rows_being_predicted() -> None:
    artifacts = load_model_artifacts()
    dataframe = mutable_feature_rows(3)
    dataframe.loc[dataframe.index[1], artifacts.feature_columns[0]] = "bad"
    predictions = predict_dataframe(dataframe, artifacts)

    assert predictions[0]["predictionStatus"] == "available"
    assert predictions[1]["predictionStatus"] == "unavailable"
    assert predictions[2]["predictionStatus"] == "available"


def test_probabilities_sum_to_one() -> None:
    artifacts = load_model_artifacts()
    predictions = predict_dataframe(load_feature_rows(3), artifacts)

    for record in predictions:
        assert_available_prediction(record)
        assert math.isclose(sum(record["classProbabilities"].values()), 1.0, rel_tol=0, abs_tol=1e-5)


def test_predicted_class_index_equals_probability_argmax() -> None:
    artifacts = load_model_artifacts()
    record = predict_dataframe(load_feature_rows(1), artifacts)[0]
    labels = list(artifacts.label_mapping.values())
    probabilities = [record["classProbabilities"][label] for label in labels]

    assert record["predictedClassIndex"] == int(np.argmax(probabilities))


def test_predicted_attack_type_matches_label_mapping() -> None:
    artifacts = load_model_artifacts()
    record = predict_dataframe(load_feature_rows(1), artifacts)[0]

    assert record["predictedAttackType"] == artifacts.label_mapping[record["predictedClassIndex"]]


def test_model_confidence_equals_max_probability() -> None:
    artifacts = load_model_artifacts()
    record = predict_dataframe(load_feature_rows(1), artifacts)[0]

    assert math.isclose(record["modelConfidence"], max(record["classProbabilities"].values()), abs_tol=1e-8)


def test_prediction_margin_is_top_minus_second_probability() -> None:
    artifacts = load_model_artifacts()
    record = predict_dataframe(load_feature_rows(1), artifacts)[0]
    probabilities = sorted(record["classProbabilities"].values(), reverse=True)

    assert math.isclose(record["predictionMargin"], probabilities[0] - probabilities[1], abs_tol=1e-8)


def test_sha256_provenance_matches_artifact_files() -> None:
    artifacts = load_model_artifacts()

    assert artifacts.provenance["modelSha256"] == sha256_file(DEFAULT_MODEL_PATH)
    assert artifacts.provenance["featureSchemaSha256"] == sha256_file(DEFAULT_FEATURE_COLUMNS_PATH)
    assert artifacts.provenance["preprocessingConfigSha256"] == sha256_file(DEFAULT_PREPROCESSING_CONFIG_PATH)
    assert artifacts.provenance["labelMappingSha256"] == sha256_file(DEFAULT_LABEL_MAPPING_PATH)


def test_prediction_path_does_not_require_ground_truth() -> None:
    artifacts = load_model_artifacts()
    predictions = predict_dataframe(load_feature_rows(2), artifacts)

    assert len(predictions) == 2
    assert all("groundTruth" not in record for record in predictions)
    assert all("rawLabel" not in record for record in predictions)
    assert all("mappedAttackType" not in record for record in predictions)


def test_unsupported_infiltration_is_represented_in_artifacts() -> None:
    artifacts = load_model_artifacts()
    preprocessing_config = artifacts.preprocessing_config

    assert "Infiltration" not in set(artifacts.label_mapping.values())
    assert preprocessing_config["missingExpectedAttackTypes"] == ["Infiltration"]


def test_prediction_output_can_be_regenerated_from_committed_artifacts() -> None:
    artifacts = load_model_artifacts()
    predictions = predict_dataframe(load_feature_rows(5), artifacts)
    comparison = compare_predictions(predictions)

    assert len(predictions) == 5
    assert all(record["predictionStatus"] == "available" for record in predictions)
    assert comparison is not None


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value))
    return suite
