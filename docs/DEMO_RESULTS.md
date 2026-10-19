# Saved demonstration results

Duke Gateway runs saved on October 15, 2026:

| Scenario | Rule | Rating | Priority | Model turns | Tool executions | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline | R6 | Insufficient evidence | Insufficient evidence | 3 | 4 | 9.688 |
| Positive | R1 | High | Critical | 3 | 4 | 10.112 |

Both runs used live CNA, CERT-EU, and CISA lookups. Their technical checks passed; evidence review was pending in the saved checklists.

The baseline retains unknown firmware and SSL-VPN settings. The positive case uses simulated settings for one gateway instance. Neither establishes local compromise.

| Run | Assessment | Tool trace | Model messages | Checklist |
| --- | --- | --- | --- | --- |
| Baseline | [Report](../artifacts/runs/baseline-duke-demo-2026-10-15/assessment.md) | [Trace](../artifacts/runs/baseline-duke-demo-2026-10-15/tool_trace.json) | [Messages](../artifacts/runs/baseline-duke-demo-2026-10-15/model_messages.json) | [Checks](../artifacts/runs/baseline-duke-demo-2026-10-15/demonstration_checklist.json) |
| Positive | [Report](../artifacts/runs/positive-duke-demo-2026-10-15/assessment.md) | [Trace](../artifacts/runs/positive-duke-demo-2026-10-15/tool_trace.json) | [Messages](../artifacts/runs/positive-duke-demo-2026-10-15/model_messages.json) | [Checks](../artifacts/runs/positive-duke-demo-2026-10-15/demonstration_checklist.json) |

See the [walkthrough](DEMO_WALKTHROUGH.md) to run a fresh demonstration.
