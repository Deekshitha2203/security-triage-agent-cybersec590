# Group contributions and evidence review

**Members:** Atharva Ashish Jog, Varun Bhanushali, Shweta Mittal, Deekshitha Manjunatha Reddy.

## Contribution record

Each member owned a set of files and was responsible for the code, design section and documentation for that part. Others reviewed and sent suggestions to the owner. All four members ran the agent and reviewed the outputs.

| Member | Responsible for | Contribution |
| --- | --- | --- |
| Atharva Ashish Jog | `triage/policy.py`, `triage/assessment.py`; policy, impact criteria and output contract sections of `STEP_1_DESIGN.md` | Provided the threat-case proposal with collaborators, supplied the six-rule priority policy, approved implementation and selected Duke AI Gateway. Worked on the R1–R6 risk policy, firmware version checks and assessment building. |
| Varun Bhanushali | `triage/tools.py`, `scripts/prepare_inputs.py`, `data/environment/`, `data/evidence/`; environment, sources and tool contract sections of `STEP_1_DESIGN.md` | Worked on the environment snapshot, test variants, and the CNA, CERT-EU and CISA KEV lookup tools. |
| Shweta Mittal | `triage/models.py`, `triage/agent.py`, `triage/__main__.py`, `triage/common.py`, `triage/__init__.py`, `config/agent.json`; workflow, model integration and runtime limits sections of `STEP_1_DESIGN.md` | Worked on the Duke AI Gateway integration, the model and tool loop, and the command line interface. |
| Deekshitha Manjunatha Reddy | `tests/test_triage.py`, `scripts/evaluate.py`, `scripts/package_submission.py`, README, requirements, Git settings and submission documentation; acceptance tests and final review of `STEP_1_DESIGN.md` | Worked on the tests, evaluation and packaging scripts, ran the real Duke baseline and positive runs, the controlled failure and the full evaluation (11/11), and updated the README and submission docs. |

**AI assistance disclosure:** Codex assisted with external-source research, Step 1 drafting, Python implementation, synthetic variants, automated tests, report generation and documentation. Each member reviewed and is responsible for the files they own. The group is responsible for verifying sources, technical assumptions, policy interpretations and final submission. AI output does not substitute for the required group member evidence review.

## Policy consensus

The supplied six rules define the expected results. Do not claim consensus was measured merely because automated tests passed.

- Members participating: Atharva Ashish Jog, Varun Bhanushali, Shweta Mittal, Deekshitha Manjunatha Reddy.
- Expected-result signoff: all four members agreed on the expected results for the R1–R6 policy (baseline R6, positive R1, fixed version R5, internal major impact R2, limited impact R3, minor impact R4, decisive conflict Review).
- Disagreements and resolution: none.
- Link/path to actual testing results reviewed: `artifacts/testing/TESTING_REPORT.md` and `artifacts/testing/results.json`.

## Assessment review

Each member reviewed the part of the output linked to the files they own.

- Run directory and run ID: `artifacts/runs/baseline-duke-demo-2026-10-15` (`ea7dfad4-9925-4f97-a7aa-e77bf1f39edf`) and `artifacts/runs/positive-duke-demo-2026-10-15` (`e3a890a3-d6fd-4704-be01-e8beb6fc79e5`).
- Asset/CVE/snapshot and simulated scope (N02, CVE-2024-21762, northbridge-docx-v1): checked by Varun.
- Cited source payloads, locators, dates, cache labels and version comparisons: checked by Varun.
- SSL-VPN and attack-path prerequisites, Internet reachability: checked by Atharva.
- Major/limited/minor consequences and assumptions against the policy: checked by Atharva.
- Model tool requests, call IDs and returned results: checked by Shweta.
- Rule, rating, priority, unknowns/conflicts, confidence and actions against the expected results: checked by Deekshitha.
- Decision: accepted. The baseline correctly gives Insufficient evidence (R6) because firmware and SSL-VPN are unknown, and the positive scenario correctly gives High / Critical (R1).

The generated `demonstration_checklist.json` deliberately leaves human review false. Update it only after a group member actually reviews the evidence; preserve the signoff in this record. Do not change replay's `real_model_used` flag to true.