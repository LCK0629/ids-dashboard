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
├── docs/
│   ├── features.md
│   ├── progress-log.md
│   ├── proposal.md
│   ├── questions.md
│   └── tech-stack.md
├── prototype-demo/
│   ├── app.js
│   ├── index.html
│   └── styles.css
└── README.md
```

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
- [Progress Log](docs/progress-log.md)
- [Questions](docs/questions.md)
