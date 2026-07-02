# Tech Stack Notes

## Frontend Options

- React
- Vue
- Next.js

Recommended choice: React or Next.js, because they are suitable for building interactive dashboards and reusable UI components.

## Backend Options

- Flask
- FastAPI
- Node.js / Express

Recommended choice: FastAPI, because it works well with Python-based data processing and can provide clean API endpoints for the dashboard.

## Database Options

- SQLite
- PostgreSQL

Recommended choice for prototype: SQLite. It is simple, local, and suitable for an FYP prototype.

Recommended choice for larger deployment: PostgreSQL.

## Visualization Libraries

- Chart.js
- Recharts
- D3.js

Recommended choice: Recharts or Chart.js for faster development.

## Dataset Options

- CSE-CIC-IDS2018
- CICIDS2017
- UNSW-NB15
- NSL-KDD
- Simulated IDS alert logs

Formal dataset decision: use CSE-CIC-IDS2018. It is newer than CICIDS2017, suitable for intrusion detection, and can be sampled and converted into dashboard-style IDS alerts.

Stage 1 will not build the full dataset pipeline yet. The planned data handling flow is:

```txt
CSE-CIC-IDS2018 raw CSV files
-> sample selected rows
-> convert sampled flow records into dashboard alert JSON
-> use the converted alerts in the IDS dashboard prototype
```

Stage 1 dataset-related files will be placed under:

```txt
stage-1/
|-- data/
|   |-- raw/
|   |   `-- cse-cic-ids2018/
|   `-- processed/
|       `-- sample-alerts.json
`-- scripts/
    `-- sample_cse_cic_ids2018.py
```

The current mock alert data remains in use for dashboard UX testing, feedback button testing, adaptive scoring testing, and Investigations / Feedback Model / Reports view testing before full dataset integration.

## Adaptive Logic Options

- Rule-based scoring
- Simple machine learning model
- Hybrid rule-based and feedback-based scoring

Recommended initial approach: rule-based adaptive scoring. This is easier to explain, test, and demonstrate during FYP evaluation.

## Possible Architecture

Frontend dashboard sends user feedback to the backend API. The backend stores alert data and feedback in the database. The scoring logic recalculates alert priority based on feedback history. The frontend displays updated scores, charts, and summary reports.

## Personal Notes

- 中文备注：先做 rule-based，不要一开始就把 ML 做得太复杂。
- 重点是 dashboard + feedback loop + clear evaluation。
