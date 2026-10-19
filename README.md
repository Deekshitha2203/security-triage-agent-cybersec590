# Security Triage Agent

Assesses CVE-2024-21762 against the Northbridge N02 FortiOS VPN environment using the agreed R1–R6 rules.

## Setup

Use Python 3.12 or newer. No external packages are required.

```bash
python3 -m triage configure
python3 -m triage doctor
```

Configuration saves the Duke Gateway key in the ignored `.env` file. Keep credentials out of Git and saved results.

## Run

```bash
python3 -m triage run --scenario baseline --provider duke --evidence-mode auto --output artifacts/runs/baseline-duke
python3 -m triage run --scenario positive --provider duke --evidence-mode auto --output artifacts/runs/positive-duke
```

The inputs are in `data/environment/`. The baseline leaves firmware and SSL-VPN configuration unknown, so its expected result is **Insufficient evidence**. The positive scenario uses simulated values and expects **High / Critical**.

Each output folder contains `assessment.md`, `assessment.json`, the input snapshot, source evidence, tool trace, and model messages. Reports include the rule, rating, priority, evidence references, uncertainty, and recommended actions.

`auto` fetches public evidence and falls back to the verified cache when needed. Use `live` to disable fallback or `cached` to use saved evidence.

## Test

```bash
python3 -m unittest discover -s tests -v
```

For an offline workflow check, use `--provider replay --evidence-mode cached` with the run command. Replay uses scripted responses rather than a live model.

See [the design](docs/STEP_1_DESIGN.md) for the risk rules and [the demo walkthrough](docs/DEMO_WALKTHROUGH.md) for the presentation steps.
