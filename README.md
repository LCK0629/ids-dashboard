# Human-in-the-Loop Intrusion Detection Dashboard

## Project Information

- Project ID: CSIT-26-S3-07
- Proposed Title: Human-in-the-Loop Intrusion Detection Dashboard
- Student:
- Supervisor:
- Current Status: High-fidelity demo separated from future formal development

## Project Description

This project develops a next-generation intrusion detection interface that combines automated security alerts with human feedback. The dashboard allows administrators to review, label, and respond to alerts, then uses their feedback to improve alert prioritization and reduce false positives.

## Repository Structure

```txt
.
|-- docs/
|   |-- environment.md
|   |-- features.md
|   |-- progress-log.md
|   |-- proposal.md
|   |-- questions.md
|   |-- signature-based-detection.md
|   `-- tech-stack.md
|-- prototype-demo/
|   |-- app.js
|   |-- index.html
|   `-- styles.css
|-- stage-1/
|   |-- data/
|   |-- notebooks/
|   |-- scripts/
|   |-- alert-schema.md
|   |-- data-processing-summary.txt
|   |-- preprocessing-log.md
|   `-- README.md
|-- stage-2/
|   |-- core/
|   |-- data/
|   |-- rules/
|   |-- scripts/
|   `-- README.md
|-- stage-3/
|   |-- evaluation/
|   |-- models/
|   |-- notebooks/
|   |-- outputs/
|   |-- scripts/
|   `-- README.md
|-- stage-4/
|   |-- core/
|   |-- evaluation/
|   |-- outputs/
|   |-- scripts/
|   `-- README.md
`-- README.md
```

## Formal Development Direction

The final system direction is a Hybrid Human-in-the-Loop IDS Dashboard, developed in stages:

```txt
Stage 1: CSE-CIC-IDS2018 dataset preprocessing
Stage 2: Flow-based signature detection
Stage 3: XGBoost ML Detection Engine
Stage 4: Fusion Engine
Stage 5: Human feedback and Exception Memory
Stage 6: Dashboard integration
Stage 7: Evaluation
```

Signature-based detection:
Identifies known attack patterns using lightweight flow-based rules.

Machine-learning detection:
Uses CSE-CIC-IDS2018 flow features to train a future XGBoost IDS classifier.

Fusion engine:
Combines signature and ML results into final alert priority.

Human feedback:
Administrator feedback adjusts repeated false-positive patterns through Exception Memory.

## Environment Requirements

This project uses two lightweight development environments:

- Node.js: used for Stage 2 signature engine scripts and future dashboard integration.
- Python: used for Stage 1 preprocessing and future Stage 3 ML experiments.

### Node.js

Recommended version:

```txt
Node.js 20 or later
```

Check installation:

```powershell
node -v
npm -v
```

Run the Stage 2 signature demo:

```powershell
node stage-2/scripts/run-signature-demo.js
```

If Node.js is not installed, a portable Node.js zip can be used without modifying the system PATH.

### Python

Recommended version:

```txt
Python 3.10 or later
```

Python is used for data preprocessing notebooks/scripts. Python dependencies will be formalized later through `requirements.txt`.

More details are documented in [Environment Setup](docs/environment.md).

## Prototype Demo

The `prototype-demo` folder contains a frontend-only high-fidelity demo. The alert data is hardcoded, but the dashboard is dynamic and simulates the final system behavior.

To run the prototype locally:

```powershell
python -m http.server 4173 --bind 127.0.0.1
```

Then open:

```txt
http://127.0.0.1:4173/prototype-demo/index.html
```

Future formal development can be added separately without mixing it with the demo, for example in an `app/`, `frontend/`, or `src/` folder.

## Stage 1 Dataset Plan

Stage 1 will use CSE-CIC-IDS2018 as the formal dataset source. It is newer than CICIDS2017, suitable for intrusion detection, and can be sampled into dashboard-style IDS alerts.

The Stage 1 data handling plan is:

```txt
CSE-CIC-IDS2018 raw CSV files
-> sample selected rows
-> convert sampled flow records into dashboard alert JSON
-> use the converted alerts in the IDS dashboard prototype
```

Dataset files and processing scripts will be placed under the `stage-1/` folder. The current mock alert data remains in use for dashboard UX testing, feedback button testing, adaptive scoring testing, and Investigations / Feedback Model / Reports view testing before full dataset integration.

## Prototype Highlights

- Realistic SOC-style intrusion alert dashboard.
- Hardcoded IDS alerts for demonstration.
- Clickable alert queue with a detailed explanation panel.
- Risk score, trigger reason, risk factors, evidence, and recommended action for each alert.
- Human feedback buttons for True Positive, False Positive, Suspicious, and Benign.
- Dynamic adaptive scoring that updates similar alerts after feedback.
- KPI cards and charts that update immediately after analyst feedback.

## Main Objectives

- Build an interactive dashboard for intrusion detection alerts.
- Support human feedback on alert classification and priority.
- Adapt alert scoring based on administrator responses.
- Improve usability for security alert triage.
- Evaluate whether feedback can reduce false positives and improve operational efficiency.

## Documentation

- [Proposal](docs/proposal.md)
- [Features](docs/features.md)
- [Tech Stack](docs/tech-stack.md)
- [Environment Setup](docs/environment.md)
- [Signature-Based Detection Design](docs/signature-based-detection.md)
- [Progress Log](docs/progress-log.md)
- [Questions](docs/questions.md)
