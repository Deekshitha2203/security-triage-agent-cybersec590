# Contributions and Review

**Members:** Atharva Ashish Jog, Varun Bhanushali, Shweta Mittal, Deekshitha Manjunatha Reddy

## Who did what

Each of us owned a part of the code and the matching section of the design doc. The others reviewed it and sent suggestions. All four of us ran the agent and looked at the outputs.

| Member | Files | Work |
| --- | --- | --- |
| Atharva Ashish Jog | `triage/policy.py`, `triage/assessment.py` | Proposed the threat case and wrote the six rule policy. Picked Duke AI Gateway. Built the R1 to R6 logic and the firmware version checks. Also built the assessment output. Wrote the policy and impact sections of the design along with the output format. |
| Varun Bhanushali | `triage/tools.py`, `scripts/prepare_inputs.py`, `data/environment/`, `data/evidence/` | Built the environment snapshot and the test variants. Wrote the lookup tools for the CNA record and CERT-EU, plus the CISA KEV lookup. Wrote the environment and tool contract sections of the design. |
| Shweta Mittal | `triage/models.py`, `triage/agent.py`, `triage/__main__.py`, `triage/common.py`, `triage/__init__.py`, `config/agent.json` | Connected the agent to Duke AI Gateway and built the model and tool loop. Also built the command line. Wrote the workflow and model integration sections of the design. |
| Deekshitha Manjunatha Reddy | `tests/test_triage.py`, `scripts/evaluate.py`, `scripts/package_submission.py`, README | Wrote the tests and the evaluation script. Built the packaging script. Merged all four branches into the final version and checked the merged code (29 unit tests and 11 evaluation cases pass). Ran the final Duke runs and the controlled failure. Wrote the acceptance test section of the design and did the final design review. |

**AI use:** We used Codex to help with research and with writing code and docs. Each member reviewed the files they own. AI output does not replace our own review of the evidence.

## Policy agreement

Before running the tests, all four of us agreed on the expected result for each rule.

| Case | Expected |
| --- | --- |
| Baseline (firmware and SSL VPN unknown) | R6, Insufficient evidence |
| Positive scenario | R1, High, Critical |
| Fixed firmware version | R5, Low, Informational |
| Internal only with major impact | R2, High, High |
| Limited impact | R3, Medium, Medium |
| Minor impact | R4, Low, Low |
| Missing evidence | R6, Insufficient evidence |
| Conflicting evidence | R6, Review |

We had no disagreements. Passing tests alone is not our agreement. We set these expected results first and then checked them against `artifacts/testing/results.json` and `artifacts/testing/TESTING_REPORT.md`.

## Review of the final runs

| Run | Folder | Run ID |
| --- | --- | --- |
| Baseline, Duke model | `artifacts/runs/final-baseline-duke` | `37fb4f34-f06e-482c-9ed9-8b82f13dc5bf` |
| Positive, Duke model | `artifacts/runs/final-positive-duke` | `8fe57c8f-3e5b-4d97-87da-911d6c77f393` |
| Controlled failure | `artifacts/runs/final-failure-replay` | `1ce3ac4b-ff83-466e-9d17-5205c4550bef` |

| What we checked | Who |
| --- | --- |
| Asset and CVE scope in the snapshot | Varun |
| Cited sources with their dates and cache labels | Varun |
| Whether the CVE applies (firmware and SSL VPN) | Atharva |
| Internet reachability | Atharva |
| Impact and assumptions against the policy | Atharva |
| Model tool requests and returned results | Shweta |
| Final rule and rating against the expected results | Deekshitha |

**Decision: accepted.** The baseline gives R6 because the firmware and the SSL VPN setting are unknown. The positive scenario gives High and Critical under R1. The controlled failure stops at R6 and does not treat the failed lookup as safe.

The `demonstration_checklist.json` files keep human review as false because the code can't confirm that a person checked it. This doc is our sign off.