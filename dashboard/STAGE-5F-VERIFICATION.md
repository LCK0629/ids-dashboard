# Stage 5F Verification

Stage 5F verifies the final static dashboard without changing detection, fusion, adaptation, guardrail, or queue-ranking semantics.

## Production Bundle

| Measure | Before | After |
|---|---:|---:|
| Largest JavaScript chunk | 5,279,611 bytes | 270,790 bytes |
| Total production JavaScript | 5,279,611 bytes | 270,790 bytes |
| Separate analyst JSON asset | Bundled into JavaScript | 7,772,471 bytes |
| Vite 500 kB warning | Present | Not present |

The canonical analyst JSON remains in `dashboard/src/data/analyst-alerts.v1.json`. Vite emits it as a hashed asset, and `App.tsx` fetches and validates it before operational records are rendered.

## Verification Matrix

| Area | Result | Evidence |
|---|---|---|
| Data integrity | Pass | 995 records; approved score and ordering fingerprints unchanged |
| Detection evidence | Pass | Stage 4 regression suite and dashboard automated-evidence tests |
| TreeSHAP | Pass | Signed predicted-class evidence retained with zero scoring influence |
| HITL explanation | Pass | Stage 5D decision-chain and semantic tests |
| Queue workflow | Pass | 524 Active Alerts under the approved Stage 5E criteria |
| Session preview | Pass | Action deltas, review semantics, and immutable Detection Score tests |
| Guardrails | Pass | Stage 5 core guardrail tests and frozen demonstration scores |
| Failure handling | Pass | Fetch, invalid JSON/schema, evaluator, demo, empty-filter, and no-selection states |
| Responsive | Pass | 360, 390, 768, 1024, and 1440 CSS/viewport checks |
| Accessibility | Pass | Native labels, fieldsets, pressed/current states, keyboard rows, and visible focus |
| Performance | Pass | Analyst JSON removed from the JavaScript module payload |
| GitHub Pages | Pass | Vite production base remains `/ids-dashboard/`; deployment workflow retained |
| Ground-truth isolation | Pass | No forbidden ground-truth fields in the analyst artifact |
| Formal/demo separation | Pass | Six controlled demo IDs remain outside all 995 formal records |

## Remaining Limits

- The dashboard is a static research prototype with no backend, live capture, authentication, or persistent analyst feedback.
- Replay sequence comes from artifact order and is not evidence of network arrival chronology.
- The analyst JSON is downloaded as a separate static asset and remains about 7.77 MB uncompressed.
- The current six-class XGBoost model does not support Infiltration prediction.
