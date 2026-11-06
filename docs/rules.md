# Detection rules

| Rule | Severity | Signal | Important limitation |
|---|---|---|---|
| SCS001 | High | Unusual package identifier | Syntax anomaly only |
| SCS002 | Low | Duplicate component/version in supplied inputs | Can be intentional across sources |
| SCS003 | Critical | Built-in lookalike-name watchlist match | Not proof of malicious package |
| SCS004 | Medium | Direct dependency not pinned to exact version | Lockfiles can still provide reproducibility |
| SCS006 | High | Package script contains remote-shell/download pattern | Manual review required |
| SCS007 | High | GitHub Action uses mutable ref | Pin verified full commit SHA |
| SCS008 | High | Privileged pull_request_target trigger | Risk depends on workflow behavior |
| SCS009 | High | Workflow write-all permissions | Reduce to least privilege |

The analyzer intentionally reports evidence and remediation rather than claiming exploitability. It does not execute package scripts or resolve the complete dependency graph for arbitrary ecosystems.
