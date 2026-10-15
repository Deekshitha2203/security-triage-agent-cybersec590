# Implementation and verification notes

The group approved Step 1 and added separate priorities to the six-rule policy. The implementation uses one Python application with direct tools and separate modules for orchestration, model adapter, source lookup, policy, validation and safe output persistence.

## Design changes

| Design item | Implementation | Reason |
| --- | --- | --- |
| Proposed local Ollama Qwen3 | Duke AI Gateway selected by the group; configurable model, default `GPT 4.1` | No local Ollama installation was available; user explicitly selected Duke |
| Source enum including vendor and NVD | CNA and CERT-EU vulnerability lookup plus CISA KEV | These authoritative sources supply verifiable version, component and exploitation evidence; full vendor/NVD retrieval was inaccessible during design research |
| Model drafts rationale | Model selects attributed claim/action IDs; code renders the supported wording | Prevents arbitrary narrative assertions and fabricated citations; real model still chooses evidence queries and final synthesis |
| Referenced canonical environment JSON | DOCX-derived scoped JSON and explicitly simulated variants | Companion JSON/CSV/script files were absent; exact missing firmware, SSL-VPN, flow and cohort facts remain unknown |
| Optional tracing | Sanitized model messages, tool trace, run manifest and demonstration checklist included | Supports attribution, controlled-failure testing and Assignment 4 baseline reuse |
| Framework and dependencies | Python standard library only, tested under 3.12.3 | Keeps setup and submission reproducible; no framework is required by the assignment |

The positive test assesses one explicitly simulated gateway instance. It does not establish uniform firmware/configuration across the pair or assert that Northbridge is compromised. The baseline remains a cohort assessment with decisive unknowns.

## Technical controls

- Only three read-only tool names and fixed source URLs are allowed. Strict arguments constrain asset, CVE, snapshot and source.
- Unknown versions/builds are unknown; FortiOS and FortiProxy version ranges are not conflated.
- Cache hashes and source URLs are verified before use. Save exact public source payloads or the documented selected KEV excerpt.
- External instructions are not accepted as tool definitions or policy. Model final synthesis cannot alter the policy result or invent claim IDs.
- HTTP redirects are refused. Credentials are sent only to the fixed Duke endpoint and are removed from persisted inputs/outputs.
- Host limits total tool executions, model turns, HTTP/model timeouts and run duration. Missing setup or execution failure is explicit and never converted to a successful replay.

## Evidence acquisition

Included public evidence was downloaded from the official CVE list, CISA's official KEV data repository, and CERT-EU. The `*.meta.json` files record actual acquisition timestamps and hashes. Cached use is labeled cached, not live. The KEV file is a scoped excerpt for this CVE with the original catalog locator/hash retained; it is not a general-purpose full catalog.

Source metrics are retained verbatim, including source-specific severity metadata. These metrics do not determine the group's local rating or priority. CISA's historical catalog due date is not the course deadline or an imposed Northbridge SLA.

## Verification and remaining work

Automated tests and expected-versus-actual results are saved separately under `artifacts/testing/`. Scripted replay verifies the complete application path and policy behavior, not real-model quality. The real-model demonstration is complete only when its run checklist confirms real model use, returned evidence, checked synthesis and actual human review.

Group members must independently check source locators and impact reasoning, record consensus, identify their actual contributions, and record the demo if they do not present in class. No automated output claims those human steps happened.
