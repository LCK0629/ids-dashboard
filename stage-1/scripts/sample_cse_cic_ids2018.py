"""Stage 1 skeleton for sampling CSE-CIC-IDS2018 into dashboard alerts.

This script is intentionally a placeholder. It documents the planned data
preparation steps without implementing the full dataset processing pipeline.
"""

from pathlib import Path


RAW_DATA_DIR = Path("stage-1/data/raw/cse-cic-ids2018")
PROCESSED_OUTPUT = Path("stage-1/data/processed/sample-alerts.json")


def load_csv_files(raw_data_dir: Path):
    """Load CSE-CIC-IDS2018 CSV files from the raw data directory."""
    raise NotImplementedError("Stage 1 placeholder: CSV loading is not implemented yet.")


def clean_column_names(dataframe):
    """Normalize CSV column names for easier processing."""
    raise NotImplementedError("Stage 1 placeholder: column cleaning is not implemented yet.")


def sample_benign_and_attack_rows(dataframe):
    """Sample selected benign and attack rows from the dataset."""
    raise NotImplementedError("Stage 1 placeholder: row sampling is not implemented yet.")


def convert_rows_to_dashboard_alerts(rows):
    """Convert sampled flow records into dashboard alert JSON objects."""
    raise NotImplementedError("Stage 1 placeholder: alert conversion is not implemented yet.")


def export_sample_alerts(alerts, output_path: Path):
    """Export dashboard alert JSON to the processed output path."""
    raise NotImplementedError("Stage 1 placeholder: JSON export is not implemented yet.")


def main():
    """Document the intended Stage 1 pipeline sequence."""
    csv_data = load_csv_files(RAW_DATA_DIR)
    cleaned_data = clean_column_names(csv_data)
    sampled_rows = sample_benign_and_attack_rows(cleaned_data)
    alerts = convert_rows_to_dashboard_alerts(sampled_rows)
    export_sample_alerts(alerts, PROCESSED_OUTPUT)


if __name__ == "__main__":
    main()

