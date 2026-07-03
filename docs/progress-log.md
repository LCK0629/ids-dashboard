# Progress Log

## Week 1

- Understood the project title and description.
- Identified the main idea: combine intrusion detection alerts with human feedback.
- Created initial documentation structure.
- Listed possible dashboard features and technology choices.
- Created a high-fidelity hardcoded frontend prototype using `prototype-demo/index.html`, `prototype-demo/styles.css`, and `prototype-demo/app.js`.
- Added dynamic SOC-style dashboard UI with alert queue, explanation panel, feedback controls, adaptive scoring, KPI cards, and charts.
- Verified that feedback changes risk scores and updates dashboard metrics.
- Separated documentation into `docs/` and the current demo into `prototype-demo/` so future formal development can be added cleanly.

## Week 2

- Fixed sidebar view-switching UX so Operations, Investigations, Feedback Model, and Reports behave like separate views.
- Ensured hidden sections are fully removed from display, sidebar active state stays consistent, and switching views scrolls back to the top of the selected workspace.
- Documented the Stage 1 dataset plan: CSE-CIC-IDS2018 will be the formal dataset source, sampled from raw CSV files and converted into dashboard-style IDS alert JSON under the future `stage-1/` folder.
- Selected CSE-CIC-IDS2018 as the formal dataset for Stage 1.
- Added Stage 1 folder structure for raw data, processed alert JSON, and sampling script preparation.
- Kept current prototype mock data unchanged.
- Added Stage 1 alert schema documentation to define the processed dashboard alert format for future CSE-CIC-IDS2018 integration.
- Added a Colab/Jupyter preprocessing notebook template for CSE-CIC-IDS2018 Stage 1 data exploration.
- Added a preprocessing log to record dataset files, sampling ratio, cleaning decisions, and output JSON details.
- Kept final reusable preprocessing logic planned under `stage-1/scripts/sample_cse_cic_ids2018.py`.
- Inspected the local CSE-CIC-IDS2018 `archive.zip` and updated the notebook to handle its mixed CSV schema, including files without `Src IP` and `Dst IP` columns.
- Improved the Stage 1 preprocessing notebook with stratified sampling, formal label mapping, severity/risk score mapping, stronger schema validation, and preprocessing summary records.
- Added a Stage 1 data processing summary text file describing the planned CSE-CIC-IDS2018 loading, cleaning, sampling, label mapping, severity/risk mapping, alert conversion, validation, and JSON export workflow.
- Validated the generated Stage 1 `sample-alerts.json`, copied it into `stage-1/data/processed/`, and recorded preprocessing run details including sample counts, distributions, validation checks, and current label-mapping limitation.
- Updated the Stage 1 preprocessing notebook to audit labels across all available CSE-CIC-IDS2018 CSV files and sample by mapped dashboard attack type so future samples can cover all available attack categories.
- Finalized Stage 1 attack label mapping so web attack variants such as `Brute Force -XSS`, `SQL Injection`, and `Brute Force -Web` map to `Web Attack`, and repaired the existing repository sample so it no longer contains `Unknown Attack` records.
- Validated and copied the final 1000-alert Stage 1 processed sample into `stage-1/data/processed/sample-alerts.json`, with 500 benign alerts, 500 malicious alerts, and no `Unknown Attack` records.

## Week 3

- Refined the project direction into a staged Hybrid Human-in-the-Loop IDS Dashboard.
- Planned the formal pipeline as Stage 1 dataset preprocessing, Stage 2 flow-based signature detection, Stage 3 XGBoost ML detection, Stage 4 fusion, Stage 5 human feedback and Exception Memory, Stage 6 dashboard integration, and Stage 7 evaluation.
- Started Stage 2 by adding a standalone flow-based signature detection engine.
- Corrected the Stage 2 signature engine direction so rules use flow-level features instead of dataset-derived `attackType`, while `attackType` and `groundTruth` remain for evaluation only.
- Split Stage 1 processed outputs into feature-only detection input, ground-truth evaluation labels, and a dashboard-ready labelled sample to prevent future detection engines from using answer fields.
- Added environment documentation for Node.js and Python requirements, including a portable Node.js option for running Stage 2 without modifying the system PATH.
- Added formal signature-based detection design documentation explaining Stage 2 flow-level rules, allowed input fields, forbidden label-derived fields, heuristic limitations, and the role of signature evidence in the later Fusion Engine.
- Hardened Stage 2 signature rules by renaming rule output metadata to `predictedAttackType`, adding prototype heuristic validation status and rationale, and generating formal post-prediction evaluation summaries.

## Week 4

- To be updated.

## Notes

Use this file to record weekly progress, decisions, problems, and next steps. Short but consistent updates are better than writing everything at the end.
