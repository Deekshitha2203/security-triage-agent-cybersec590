# Duke AI Gateway demonstration results

Both complete runs used the real Duke model and live CNA, CERT-EU and CISA lookups. All technical demonstration checks passed; human review remains pending.

| Scenario | Rule | Rating | Priority | Model turns | Tool executions | Elapsed seconds |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | R6 | Insufficient evidence | Insufficient evidence | 3 | 4 | 9.688 |
| positive | R1 | High | Critical | 3 | 4 | 10.112 |

## Inputs and interpretation

The baseline assesses the original N02 cohort. Firmware and SSL-VPN facts remain unknown, so R6 preserves uncertainty and requests decisive configuration evidence. The positive case is one explicitly simulated test instance with affected FortiOS, enabled Internet-reachable SSL-VPN and major business consequences; it supports R1 High / Critical. Neither run establishes actual compromise.

## Evidence and traces

- **baseline**: [assessment](../artifacts/runs/baseline-duke-demo-2026-10-15/assessment.md), [JSON](../artifacts/runs/baseline-duke-demo-2026-10-15/assessment.json), [model/tool messages](../artifacts/runs/baseline-duke-demo-2026-10-15/model_messages.json), [tool trace](../artifacts/runs/baseline-duke-demo-2026-10-15/tool_trace.json), [checklist](../artifacts/runs/baseline-duke-demo-2026-10-15/demonstration_checklist.json). Run ID: `ea7dfad4-9925-4f97-a7aa-e77bf1f39edf`.
- **positive**: [assessment](../artifacts/runs/positive-duke-demo-2026-10-15/assessment.md), [JSON](../artifacts/runs/positive-duke-demo-2026-10-15/assessment.json), [model/tool messages](../artifacts/runs/positive-duke-demo-2026-10-15/model_messages.json), [tool trace](../artifacts/runs/positive-duke-demo-2026-10-15/tool_trace.json), [checklist](../artifacts/runs/positive-duke-demo-2026-10-15/demonstration_checklist.json). Run ID: `e3a890a3-d6fd-4704-be01-e8beb6fc79e5`.

All saved artifacts were checked for configured credential values; none were found. Credentials are not displayed in this report.

## Recording plan

Follow [the walkthrough](DEMO_WALKTHROUGH.md). Show the design, the original input and explicit test overrides, a real model-selected tool call, its returned source evidence, both assessments, and the controlled testing report. Close `.env` and the API-key PDF before recording.

## Remaining human steps

- A group member verifies the cited passages, local assumptions and decisions, then records the actual review and policy consensus.
- Complete each member's actual contribution record.
- If the group does not present in class, record the walkthrough and provide the required video/link. No recording has been created.
- Regenerate the package after adding review records or video references.
