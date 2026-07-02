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

- CICIDS2017
- UNSW-NB15
- NSL-KDD
- Simulated IDS alert logs

Recommended prototype approach: start with simulated IDS alert logs or a cleaned public dataset sample, then expand if needed.

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

