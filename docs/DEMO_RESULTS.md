# Final demonstration results

The final run manifests match the submitted source files. Baseline and positive runs used Duke AI Gateway and live CNA, CERT-EU, and CISA lookups. The failure run uses scripted replay.

| Run | Rule | Rating | Priority | Model turns | Tool executions | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| baseline | R6 | Insufficient evidence | Insufficient evidence | 3 | 4 | 12.164 |
| positive | R1 | High | Critical | 3 | 4 | 14.385 |
| failure | R6 | Insufficient evidence | Insufficient evidence | 6 | 6 | 0.013 |

## Saved evidence

- baseline: [assessment](../artifacts/runs/final-baseline-duke/assessment.md), [JSON](../artifacts/runs/final-baseline-duke/assessment.json), [model messages](../artifacts/runs/final-baseline-duke/model_messages.json), [tool trace](../artifacts/runs/final-baseline-duke/tool_trace.json), [checklist](../artifacts/runs/final-baseline-duke/demonstration_checklist.json), [manifest](../artifacts/runs/final-baseline-duke/baseline_manifest.json). Run ID: `37fb4f34-f06e-482c-9ed9-8b82f13dc5bf`.
- positive: [assessment](../artifacts/runs/final-positive-duke/assessment.md), [JSON](../artifacts/runs/final-positive-duke/assessment.json), [model messages](../artifacts/runs/final-positive-duke/model_messages.json), [tool trace](../artifacts/runs/final-positive-duke/tool_trace.json), [checklist](../artifacts/runs/final-positive-duke/demonstration_checklist.json), [manifest](../artifacts/runs/final-positive-duke/baseline_manifest.json). Run ID: `8fe57c8f-3e5b-4d97-87da-911d6c77f393`.
- failure: [assessment](../artifacts/runs/final-failure-replay/assessment.md), [JSON](../artifacts/runs/final-failure-replay/assessment.json), [model messages](../artifacts/runs/final-failure-replay/model_messages.json), [tool trace](../artifacts/runs/final-failure-replay/tool_trace.json), [checklist](../artifacts/runs/final-failure-replay/demonstration_checklist.json), [manifest](../artifacts/runs/final-failure-replay/baseline_manifest.json). Run ID: `1ce3ac4b-ff83-466e-9d17-5205c4550bef`.

The baseline retains unknown firmware and SSL-VPN settings. The positive case uses explicit simulated settings for one gateway instance. The controlled failure records two failed attempts for each threat lookup and disables cache fallback.

The group review is recorded in [CONTRIBUTIONS_AND_REVIEW.md](CONTRIBUTIONS_AND_REVIEW.md). Automated checklists retain their original human-review flags; the group review record is separate.

Recording: pending. See [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md) for the recording sequence.
