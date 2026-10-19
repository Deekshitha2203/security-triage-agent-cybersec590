# Implementation notes

The application uses Python's standard library and Duke AI Gateway.

| Module | Responsibility |
| --- | --- |
| `triage/agent.py` | Tool-call loop, run limits, reports, and saved run files |
| `triage/tools.py` | Environment lookup, CNA/CERT-EU lookup, and CISA KEV lookup |
| `triage/models.py` | Duke requests and offline replay responses |
| `triage/policy.py` | Version comparison and R1-R6 decisions |
| `triage/assessment.py` | Evidence-linked policy inputs, claims, actions, and synthesis validation |
| `triage/common.py` | Configuration, HTTP, hashing, redaction, and file writing |

The model chooses lookups and selects final claim/action IDs. Code applies the risk policy and checks every selected ID against the saved evidence.

The environment snapshot is derived from the supplied DOCX because its companion data files were absent. The baseline preserves unknown firmware and SSL-VPN settings. Test variants use explicit simulated overrides for one instance.

Cached sources are in `data/evidence/`. Live KEV runs save the full catalog and send only the selected entry to the model. Source modes, retrieval dates, and hashes are stored with the evidence.

Only fixed read-only tools are available. Scope checks, argument validation, bounded retries, run limits, cache verification, and secret redaction apply before results are saved.

Automated results are under `artifacts/testing/`; saved Duke runs are listed in [the demo results](DEMO_RESULTS.md). Evidence review is recorded separately from automated checks.
