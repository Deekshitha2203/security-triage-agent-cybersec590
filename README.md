# Security Triage Agent

Assesses CVE-2024-21762 against the N02 FortiOS VPN gateways in the supplied Northbridge Services environment. The model requests evidence through fixed tools; code applies the R1-R6 policy and saves a rating, priority, rationale, uncertainty, and recommended actions.

## Team

| Member | Responsibility |
| --- | --- |
| Atharva Ashish Jog | Rating policy and assessment output |
| Varun Bhanushali | Environment snapshots, source lookups, and evidence tools |
| Shweta Mittal | Duke Gateway integration, agent loop, configuration, and common utilities |
| Deekshitha Manjunatha Reddy | Tests, evaluation, packaging, and final integration |

The [contribution and review record](docs/CONTRIBUTIONS_AND_REVIEW.md) identifies the files owned by each member, policy agreement, and final-run evidence review.

## Setup

Use Python 3.12 or newer. The project uses only the standard library; no packages need to be installed. Tests and saved demonstrations were run with Python 3.12.3 and 3.12.4.

Run commands from the repository root:

```bash
python3 -m triage configure
python3 -m triage doctor
```

`configure` privately prompts for a Duke Gateway token and saves it in the ignored `.env`. Alternatively, set `LITELLM_TOKEN` in your environment. `.env.example` contains the variable names. The default model is `GPT 4.1`; `TRIAGE_MODEL` overrides it. Keep credentials out of source, output, and recordings.

## Run

```bash
python3 -m triage run --scenario baseline --provider duke --evidence-mode auto --output artifacts/runs/demo-baseline-duke
python3 -m triage run --scenario positive --provider duke --evidence-mode auto --output artifacts/runs/demo-positive-duke
```

Inputs are in `data/environment/`. The baseline preserves unknown firmware and SSL-VPN configuration and returns R6, Insufficient evidence. The positive case uses explicit simulated overrides for one gateway instance and returns R1, High / Critical.

`auto` tries live sources and uses the verified cache after failure. `live` disables fallback; `cached` uses saved sources. Every evidence record identifies its mode.

Each output folder contains the JSON and Markdown assessments, input snapshot, configuration, source payloads, model messages, tool trace, demonstration checklist, and code manifest. The saved submission runs use `final-*` folder names; the commands above use separate folders to preserve them.

## Tests and saved results

```bash
python3 -m unittest discover -s tests -v
python3 -m triage evaluate
```

The evaluator runs eleven controlled scenarios with scripted responses and cached evidence; no API key or Internet connection is needed. It writes expected and actual results to `artifacts/testing/`.

To run the controlled failure separately:

```bash
python3 -m triage run --scenario positive --provider replay --evidence-mode cached --controlled-failure threat_unavailable --output artifacts/runs/demo-failure-replay
```

| Check | Result | Evidence |
| --- | --- | --- |
| Automated tests | 29/29 pass | [Test log](artifacts/testing/UNIT_TEST_LOG.md) |
| Policy scenarios | 11/11 match expected | [Expected versus actual results](artifacts/testing/TESTING_REPORT.md) |
| Baseline, Duke model | R6, Insufficient evidence | [Assessment](artifacts/runs/final-baseline-duke/assessment.md) |
| Positive, Duke model | R1, High / Critical | [Assessment](artifacts/runs/final-positive-duke/assessment.md) |
| Controlled failure | R6, Insufficient evidence | [Assessment](artifacts/runs/final-failure-replay/assessment.md) |

The policy checks cover applicability changes, impact changes, missing/conflicting evidence, and an unavailable threat lookup. The group review is recorded separately from automated checks. The saved `final-*` runs and evaluation results provide the baseline for Assignment 4.

## Design and policy

[STEP_1_DESIGN.md](docs/STEP_1_DESIGN.md) contains the revised design activity, workflow diagram, tool contracts, rating criteria, failure handling, acceptance tests, and design changes.

| Rule | Condition | Rating | Priority |
| --- | --- | --- | --- |
| R1 | Applies, Internet-reachable vulnerable service, major impact | High | Critical |
| R2 | Applies through a supported internal path, major impact, verified absence of Internet reachability | High | High |
| R3 | Applies through a supported path, limited impact | Medium | Medium |
| R4 | Applies through a supported path, minor impact in an isolated low-value service | Low | Low |
| R5 | A required prerequisite is confirmed absent | Low | Informational |
| R6 | Decisive evidence is missing or conflicting | No rating | Insufficient evidence or Review |

Invalid or contradictory inputs require Review. A confirmed absent prerequisite gives R5; otherwise decisive gaps or conflicts give R6 before R1-R4 are considered. Unknown Internet reachability cannot be assumed false when distinguishing Critical from High priority. CVSS and KEV provide context and do not replace local applicability and impact checks.

## Sources and limitations

The original environment is `Windows_Enterprise_Environment.docx`. Derived snapshots retain unknowns and label all local evidence as simulated. The [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/21xxx/CVE-2024-21762.json), [CERT-EU advisory](https://cert.europa.eu/publications/security-advisories/2024-018/), and [CISA KEV catalog](https://github.com/cisagov/kev-data/blob/main/known_exploited_vulnerabilities.json) supply threat evidence. Cached inputs and retrieval metadata are in `data/evidence/`; each run saves the payloads it used.

This covers one CVE and a fictional, incomplete environment. The tests use controlled scenarios and do not measure general accuracy or repeated live-model performance. Human review is needed before acting on configuration assumptions or business-impact judgments. The agent recommends actions; it does not scan, patch, or establish local compromise.

## Submission

Submit the instructor-accessible repository link. Recording: pending; add the video link unless the group presents in class.

For an optional ZIP:

```bash
python3 -m scripts.package_submission
```

This creates `dist/security-triage-agent.zip`, excluding local credentials and the course API-key PDF.

Development assistance: Codex assisted with research, code, tests, and documentation.
