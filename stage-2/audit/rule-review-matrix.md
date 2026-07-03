# Stage 2B Rule Review Matrix

| Rule ID | Predicted attack type | Evidence strength | Current sample result | Main limitation | Recommendation |
|---|---|---|---|---|---|
| `SIG-FTP-BRUTE-FORCE` | Brute Force | Moderate | Matched 76 records with 0 benign hits | Cannot inspect FTP login payloads or failed login responses. | Keep as prototype heuristic |
| `SIG-SSH-BRUTE-FORCE` | Brute Force | Moderate | Matched 8 records with 0 benign hits | Cannot inspect SSH authentication failure details. | Keep as prototype heuristic |
| `SIG-DOS-HIGH-RATE-FLOW` | DoS | Moderate | Matched 83 records with 0 benign hits | High-rate legitimate traffic can also match this pattern. | Keep but validate on held-out sample |
| `SIG-DDOS-HIGH-RATE-FLOW` | DDoS | Moderate | Matched 83 records with 0 benign hits | A single flow row cannot prove distributed source behavior. | Keep but validate on held-out sample |
| `SIG-BOTNET-BEACON-FLOW` | Botnet | Experimental | Matched 84 records with 0 benign hits | Reliable botnet detection often needs host history, C2 indicators, or destination reputation. | Keep but validate on held-out sample |
| `SIG-WEB-ATTACK-FLOW` | Web Attack | Experimental | Matched 83 records with 0 benign hits | Flow-level rules cannot inspect URLs, SQL strings, XSS payloads, or HTTP parameters. | Keep but validate on held-out sample |
| `SIG-INFILTRATION-LONG-FLOW` | Infiltration | Weak | Matched 83 records with 0 benign hits | Infiltration is context-dependent and difficult to detect with flow features alone. | Needs richer features |

This matrix is for report support only. It does not tune thresholds or claim production readiness.
