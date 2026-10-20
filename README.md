# Security Triage Agent

CYBERSEC 590 group project.

We built an agent that checks one vulnerability, CVE-2024-21762, against the N02 FortiOS VPN gateways in the Northbridge Services environment and gives it a risk rating. The model decides which tools to call and what to ask them. Our code runs those tools and then applies our rating policy to the evidence. If the evidence is not enough to decide, the agent says Insufficient evidence instead of guessing.

## Team

| Member | Main work |
| --- | --- |
| Atharva Ashish Jog | Rating policy and assessment output (`triage/policy.py`, `triage/assessment.py`) |
| Varun Bhanushali | Environment snapshot and evidence lookup tools (`triage/tools.py`, `data/`) |
| Shweta Mittal | Duke AI Gateway connection and the agent loop (`triage/agent.py`, `triage/models.py`) |
| Deekshitha Manjunatha Reddy | Testing and final integration of all branches (`tests/`, `scripts/`) |

Full details and our review sign off are in `docs/CONTRIBUTIONS_AND_REVIEW.md`.

## Case

CVE-2024-21762 is an out of bounds write in the FortiOS SSL VPN. Someone who can reach the SSL VPN can run code on the device without logging in. CISA lists it in the KEV catalog, which means it has been exploited in the wild.

**Risk question:** What risk rating should CVE-2024-21762 get for the N02 FortiOS VPN gateways, based on whether it applies to them and how much damage it would cause?

| Source | What we take from it | Link |
| --- | --- | --- |
| Fortinet CNA record in the official CVE list | Affected and fixed versions plus the CVSS score | https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/21xxx/CVE-2024-21762.json |
| CERT-EU Security Advisory 2024-018 | A second source to confirm the SSL VPN attack details | https://cert.europa.eu/publications/security-advisories/2024-018/ |
| CISA KEV catalog | Whether it is known to be exploited | https://github.com/cisagov/kev-data/blob/main/known_exploited_vulnerabilities.json |
| Fortinet advisory FG-IR-24-015 | The vendor fix and workaround (planned source, could not be retrieved reliably) | https://www.fortiguard.com/psirt/FG-IR-24-015 |

Saved copies of the sources are in `data/evidence/`. Each run also saves the exact evidence it used in its own `evidence/` folder.

## Environment

We used the supplied Windows Enterprise Environment (`Windows_Enterprise_Environment.docx` in the root folder). `scripts/prepare_inputs.py` converts it into JSON snapshots in `data/environment/`.

`baseline.json` is the environment as given. In it, the firmware version of N02 is unknown and so is whether SSL VPN is turned on. So the correct answer for the baseline is Insufficient evidence, not a rating.

The other files in that folder are test variants. In each one we changed a fact on purpose, like setting a firmware version or removing Internet access. These changes are simulated and every snapshot marks them that way. The DOCX also refers to some JSON and CSV files that were never given to us. We did not make up those details.

## Design

The full design is in `docs/STEP_1_DESIGN.md`. It has the workflow diagram and the tool contracts. It also explains the rating policy and what happens when a lookup fails. Changes between the design and the final code are in `docs/IMPLEMENTATION_NOTES.md`.

How a run works:

1. Intake loads the CVE and the environment snapshot.
2. The model picks a tool and builds the arguments for it.
3. Our code checks that the request is allowed and then runs it. The result goes back to the model with its source and date.
4. This repeats until the model has what it needs or hits the tool limit.
5. Our code, not the model, applies the policy and picks the rule.
6. The model writes the summary by choosing from claims that are backed by evidence. It cannot change the rating or add new facts.
7. A group member reviews the output and the cited evidence.

| Part | File |
| --- | --- |
| Model connection (Duke AI Gateway) | `triage/models.py` |
| Agent and tool loop | `triage/agent.py` |
| Tools and source access | `triage/tools.py` |
| Rating policy | `triage/policy.py` |
| Building the assessment output | `triage/assessment.py` |
| Model settings and limits | `config/agent.json` |
| Command line | `triage/__main__.py` |

## Rating policy

The rating depends on two things. Applicability is whether the bug can actually be used against our device, meaning the firmware is in the affected range and SSL VPN is turned on. Impact is what the business loses if the device gets hit.

| Rule | When it applies | Rating | Priority |
| --- | --- | --- | --- |
| R1 | Applies, reachable from the Internet, major impact | High | Critical |
| R2 | Applies through a supported internal path, major impact, and verified absence of Internet reachability | High | High |
| R3 | Applies, limited impact on a service or small group | Medium | Medium |
| R4 | Applies, minor impact on an isolated low value system | Low | Low |
| R5 | A required condition is clearly missing | Low | Informational |
| R6 | A deciding fact is unknown or sources conflict | No rating | Insufficient evidence or Review |

We check in this order. First, if a required condition is clearly missing, like a fixed firmware version, we give R5. Next, if a deciding fact is unknown or conflicting, we give R6 and stop there. Only after that do R1 to R4 apply.

Unknown Internet access is never treated as internal only. CVSS and KEV tell us how serious the bug is and how urgent the fix is. They do not change the local rating. A failed lookup or a CVE missing from KEV never counts as proof that we are safe.

The rating is scoped to this CVE and snapshot. Confirmed disabled SSL VPN supports R5, Low / Informational; affected firmware still needs patch planning.

## Setup

You need Python 3.12 or newer. We tested on 3.12.3 and 3.12.4. The project only uses the Python standard library, so there is nothing to pip install.

Run all commands from the repo root. Don't run files inside `triage/` directly.

```
python3 -m triage doctor
python3 -m unittest discover -s tests -v
```

### Duke AI Gateway key

```
python3 -m triage configure
python3 -m triage models
python3 -m triage doctor
```

`configure` asks for your token without showing it and saves it to `.env`. That file is in `.gitignore` so it never gets committed. You can also set `LITELLM_TOKEN` in your terminal instead. `.env.example` shows the variable names with empty values.

The endpoint is `https://litellm.oit.duke.edu/v1` and the default model is GPT 4.1. You can change the model with `TRIAGE_MODEL`. Never put the key in code or screenshots.

## Running the workflow

Real model runs:

```
python3 -m triage run --scenario baseline --provider duke --evidence-mode auto --output artifacts/runs/final-baseline-duke
python3 -m triage run --scenario positive --provider duke --evidence-mode auto --output artifacts/runs/final-positive-duke
```

Controlled failure (scripted replay, no API key needed):

```
python3 -m triage run --scenario positive --provider replay --evidence-mode cached --controlled-failure threat_unavailable --output artifacts/runs/final-failure-replay
```

All 11 test cases:

```
python3 -m triage evaluate
```

`auto` tries the live source first and falls back to the saved copy if it fails. `live` only uses live sources. `cached` only uses the saved copies. Every result says whether it was live or cached.

Replay is a scripted provider we use for testing. It is not an LLM, so it does not count as the real model demo.

Each run folder has:

| File | What's in it |
| --- | --- |
| `assessment.json` and `assessment.md` | The final rating and why, plus what to do next |
| `environment_snapshot.json` | The exact environment used |
| `configuration.json` | Model and policy settings with no secrets |
| `evidence/` | The source data the run actually used |
| `model_messages.json` | What the model asked for and what it got back |
| `tool_trace.json` | Every tool call and its result, including failures |
| `demonstration_checklist.json` | Which demo requirements the run met |
| `baseline_manifest.json` | Code hashes and versions for Assignment 4 |

## Results

All of these were run on the final merged code.

| Check | Where | Result |
| --- | --- | --- |
| Unit tests | `tests/` | 29 of 29 pass |
| Evaluation cases | `artifacts/testing/results.json` | 11 of 11 match expected |
| Baseline with Duke model | `artifacts/runs/final-baseline-duke` | R6, Insufficient evidence |
| Positive scenario with Duke model | `artifacts/runs/final-positive-duke` | R1, High rating, Critical priority |
| Controlled failure | `artifacts/runs/final-failure-replay` | R6, Insufficient evidence |

### Policy checks, expected vs actual

We wrote the expected results from our policy before running anything. They are saved in `artifacts/testing/expected_results.json`. The full results are in `artifacts/testing/results.json` and `artifacts/testing/TESTING_REPORT.md`.

| Test case | What it checks | Expected | Actual | Pass |
| --- | --- | --- | --- | --- |
| `baseline` | Environment as given | R6, Insufficient evidence | R6, Insufficient evidence | Yes |
| `positive` | Simulated vulnerable and exposed gateway | R1, High, Critical | R1, High, Critical | Yes |
| `applicability-change` | **(required)** Applicability change, the CVE no longer applies | R5, Low, Informational | R5, Low, Informational | Yes |
| `disabled-component` | Required component turned off | R5, Low, Informational | R5, Low, Informational | Yes |
| `exposure-change` | Not reachable from the Internet | R2, High, High | R2, High, High | Yes |
| `impact-change` | **(required)** Impact change, impact lowered to limited | R3, Medium, Medium | R3, Medium, Medium | Yes |
| `low-impact` | Minor impact on an isolated system | R4, Low, Low | R4, Low, Low | Yes |
| `missing-evidence` | **(required)** A deciding fact is missing | R6, Insufficient evidence | R6, Insufficient evidence | Yes |
| `missing-exposure` | Internet access is unknown | R6, Insufficient evidence | R6, Insufficient evidence | Yes |
| `conflicting-evidence` | **(required)** Two sources disagree | R6, Review | R6, Review | Yes |
| `controlled-failure` | **(required)** Threat lookup made unavailable | R6, Insufficient evidence | R6, Insufficient evidence | Yes |

In the controlled failure we forced the threat lookup to fail. The agent retried once and logged both attempts in `tool_trace.json`. Then it stopped at Insufficient evidence. It did not crash and it did not treat the failure as safe.

### Review

A group member checked each final run against its cited evidence. Who checked what is in `docs/CONTRIBUTIONS_AND_REVIEW.md`. The `demonstration_checklist.json` files leave human review as false on purpose, because the code can't confirm that a person reviewed it. Our sign off is in the contributions doc instead.

## Baseline for Assignment 4

The `final-*` run folders and `artifacts/testing/` are our saved baseline. Each `baseline_manifest.json` stores the code hashes and the model settings used. Don't run `prepare_inputs` again before copying these, because it creates a new snapshot with new timestamps.

## Limitations

This covers one CVE on one set of assets. The agent does not scan or fix anything. It only reads evidence and gives a rating.

The environment is fictional and incomplete. That is why the real baseline result is Insufficient evidence. The High rating in the positive scenario comes from a simulated snapshot, so it is a test case and not a real finding.

The 11 evaluation cases use scripted replay. They show that the policy and pipeline work, but they don't show how the live model behaves every time.

Live Duke runs can sometimes stop in Review because of an API error. This happened once during our final runs, and rerunning with no changes fixed it.

We did not use Recorded Future. Threat context comes from public sources only.

## AI use

We used Codex to help with research and with writing code and docs. Each member reviewed the files they own, and we checked the sources and results ourselves.

## Submission

We are submitting this GitHub repo. If a ZIP is needed, `python3 -m scripts.package_submission` builds `dist/security-triage-agent.zip` and leaves out secrets and the API key PDF.

The demo walkthrough is in `docs/DEMO_WALKTHROUGH.md`.
Recording: pending. Add the instructor-accessible video link before submission if the group is not presenting in class.
