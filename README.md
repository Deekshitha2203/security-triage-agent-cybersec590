# Security Triage Agent

CVE-2024-21762 assessment for Northbridge Services' N02 FortiOS VPN gateways. The agent gathers attributed evidence, applies the group's R1–R6 policy, and produces a risk rating, separate priority, uncertainty, and recommended actions.

**Group:** Atharva Ashish Jog, Varun Bhanushali, Shweta Mittal, Deekshitha Manjunatha Reddy 

The original environment has unknown firmware and SSL-VPN configuration. Its supported result is **Insufficient evidence**, not a presumed vulnerability. The positive scenario is explicitly simulated and produces **High / Critical** under R1. It represents one test instance, not a confirmed finding about both gateway members.

## Portable project folder

Everything needed to run and review this project is inside this repository folder (`Security-Triage-Agent-CYBERSEC-590/` when cloned from GitHub). You can move this entire folder to another location without relying on the surrounding course folder. Open a terminal in the moved folder before running the commands below. Required assignment and environment documents are included at the project root; class slides are retained under `resources/course/`. The course API-key PDF is excluded.

```text
security-triage-agent/
  README.md                Setup and run instructions
  triage/                  Agent, model adapter, tools and risk policy
  config/                  Safe configuration
  data/                    Environment variants and public evidence
  docs/                    Design, review checklist and demo walkthrough
  scripts/                 Input preparation, evaluation and packaging
  tests/                   Automated tests
  artifacts/               Assessments, traces and test results
  resources/course/        Class reference PDFs
  dist/                    Submission ZIP and audit
```

## Setup

Use Python 3.12 or newer. Development verification used Python 3.12.3. Runtime, tests, evidence extraction and ZIP packaging use only the standard library; there are no third-party dependencies to install.

Run all commands from this project directory. This is a module-based application; do not execute individual files inside `triage/` directly.

```bash
python3 -m triage doctor
python3 -m unittest discover -s tests -v
python3 -m triage evaluate
```

The cached evidence and environment inputs are included. To regenerate environment variants from the unchanged supplied DOCX:

```bash
python3 -m scripts.prepare_inputs
```

Regeneration creates a new derived snapshot with acquisition timestamps; preserve submitted run directories before regenerating inputs for Assignment 4 comparisons.

## Duke AI Gateway configuration

The group selected Duke AI Gateway. The adapter uses its OpenAI-compatible chat-completions endpoint through Python's standard HTTP library. Default model is `GPT 4.1`, following Duke's developer guide; access and model availability must be checked against the actual key.

Configure privately:

```bash
python3 -m triage configure
python3 -m triage models
python3 -m triage doctor
```

The configuration command prompts for the token without echoing it and writes an ignored `.env` with owner-only permissions. Alternatively, provide `LITELLM_TOKEN` through your terminal's environment. `DUKE_AI_GATEWAY_API_KEY` is also accepted. Set `TRIAGE_MODEL` to another tool-capable model ID if needed. The endpoint is fixed to `https://litellm.oit.duke.edu/v1`; model-generated URLs cannot receive credentials.

Do not paste API keys into chat, source code, shell command arguments, screenshots, recordings, or submission artifacts. The course Recorded Future API-key PDF is not used and is excluded from packaging. `.env.example` contains empty placeholders. `.env` is excluded by `.gitignore` and the submission allowlist even if this folder is not initialized as a Git repository.

Integration reference: [Duke AI Gateway developer guide](https://ai.colab.duke.edu/colab-ai-blog/all-blogs/getting-started-with-dukes-ai-gateway-a-developers-guide/). It documents the endpoint, token environment variable and model discovery. No paid fund-code setup is performed by this project.

## Run the complete workflow

After configuring your Duke key:

```bash
python3 -m triage run --scenario baseline --provider duke --evidence-mode auto --output artifacts/runs/baseline-duke
python3 -m triage run --scenario positive --provider duke --evidence-mode auto --output artifacts/runs/positive-duke
```

`auto` tries each public source with a bounded retry, then uses the verified included cache if necessary. `live` permits no cache fallback. `cached` deliberately uses saved evidence. Every external result states whether it is live or cached; environment and test overrides are always simulated. Neither a lookup failure nor a valid no-match is treated as proof of safety.

The model chooses tool order and arguments, code executes each guarded request, and correlated tool results return to the model. Code then computes policy inputs and applies the documented rules. Finally, the model selects evidence-supported claim and action IDs; the host renders the approved wording. This constrains unsupported factual claims while preserving model-driven investigation and synthesis.

A successful Insufficient evidence assessment exits normally: it is a valid triage outcome. Execution/configuration failure exits with code 2 and saves a stopped/review result when output persistence is available. Missing credentials never trigger a silent switch to replay.

## Offline replay and controlled failure

```bash
python3 -m triage run --scenario baseline --provider replay --evidence-mode cached --output artifacts/runs/baseline-replay
python3 -m triage run --scenario positive --provider replay --evidence-mode cached --output artifacts/runs/positive-replay
python3 -m triage run --scenario positive --provider replay --evidence-mode cached --controlled-failure threat_unavailable --output artifacts/runs/failure-replay
```

Replay is a scripted test provider, not an LLM. It exercises the tool loop, citations, policy and output pipeline. It cannot satisfy the required real-model demonstration. `evaluate` runs eleven scenarios, saves expected outcomes before execution, and records actual results in `artifacts/testing/results.json` and `TESTING_REPORT.md`.

## Output artifacts

Every run saves:

| File | Purpose |
| --- | --- |
| `assessment.json` and `assessment.md` | Decision, priority, rule, attributed inputs, rationale, unknowns/conflicts, confidence, actions and pending human review |
| `environment_snapshot.json` | Exact simulated input and explicit overrides used |
| `configuration.json` | Safe provider/model, policy, budget and failure settings |
| `evidence/` | External payloads actually used; acquisition dates/hashes/modes also appear in the assessment register |
| `model_messages.json` | Sanitized model/tool transcript with correlated call IDs and final checked synthesis |
| `tool_trace.json` | Tool outcomes, structured failures and bounded attempt records |
| `demonstration_checklist.json` | Machine-verifiable requirements; real-model and human-review requirements remain explicit |
| `baseline_manifest.json` | Code hashes, Python/model/configuration versions, snapshot hash, source modes, usage and run limits for Assignment 4 |

## Policy

| Rule | Evidence-supported condition | Rating | Priority |
| --- | --- | --- | --- |
| R1 | Applicable, Internet-reachable vulnerable component, major consequences | High | Critical |
| R2 | Applicable supported path, major consequences, R1 demonstrably not met | High | High |
| R3 | Applicable supported path, limited service/small-group consequences | Medium | Medium |
| R4 | Applicable supported path, minor consequences in isolated low-value service | Low | Low |
| R5 | Decisive prerequisite reliably absent | Low | Informational |
| R6 | Decisive evidence missing or conflicting | No rating | Insufficient evidence or Review |

Evaluate reliable absent prerequisites before unrelated unknowns, then decisive gaps/conflicts, then R1–R4. Unknown Internet reachability cannot default to false when it determines Critical versus High priority. CVSS and KEV inform technical/exploitation context and action urgency; neither overwrites local applicability or the rule-assigned priority. Refer to `docs/STEP_1_DESIGN.md` for the detailed criteria and diagram.

## Submission

```bash
python3 -m triage package
```

This builds `dist/security-triage-agent.zip` and a file/hash audit from explicit allowlisted code, docs, inputs and run artifacts. It excludes the API-key PDF, local secrets, temp extraction files, caches of Python bytecode and private run folders. The package scans configured credential values and common credential patterns before creation. We are submitting this GitHub repository link. The ZIP command above is kept as a backup option.

Before submission, complete the actual member contribution record and group consensus/evidence review. Run a real Duke model demonstration and follow `docs/DEMO_WALKTHROUGH.md`. If the group does not present in class, record and submit the required video; the walkthrough is a recording script, not a video.

## Limitations and AI assistance

This project assesses one CVE and one bounded asset scope. It does not scan systems or execute remediation. Local data is fictional and incomplete. A complete, attributable run may conclude Insufficient evidence. The DOCX references companion JSON/CSV/lookup files that were absent; the included snapshot is a documented derived subset and does not invent missing network flows.

See `docs/IMPLEMENTATION_NOTES.md` for design deviations and `docs/CONTRIBUTIONS_AND_REVIEW.md` for actual human work and review fields. Codex assisted with research, design drafting, implementation, fixtures, automated tests and documentation. Human review and contributions are not fabricated.
