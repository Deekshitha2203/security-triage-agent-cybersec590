# Testing results

**Actual controlled results:** 11/11 passed.

Expected outcomes were saved before execution. Tests use scripted replay and verified cached public evidence; local scenario facts are simulated.
No expert/group consensus, real model performance, or completed human review is claimed.

| Case | Expected rule / rating / priority | Actual rule / rating / priority | Result |
| --- | --- | --- | --- |
| baseline | R6 / insufficient_evidence / Insufficient evidence | R6 / insufficient_evidence / Insufficient evidence | PASS |
| positive | R1 / High / Critical | R1 / High / Critical | PASS |
| applicability-change | R5 / Low / Informational | R5 / Low / Informational | PASS |
| exposure-change | R2 / High / High | R2 / High / High | PASS |
| impact-change | R3 / Medium / Medium | R3 / Medium / Medium | PASS |
| low-impact | R4 / Low / Low | R4 / Low / Low | PASS |
| missing-evidence | R6 / insufficient_evidence / Insufficient evidence | R6 / insufficient_evidence / Insufficient evidence | PASS |
| conflicting-evidence | R6 / review_required / Review | R6 / review_required / Review | PASS |
| missing-exposure | R6 / insufficient_evidence / Insufficient evidence | R6 / insufficient_evidence / Insufficient evidence | PASS |
| disabled-component | R5 / Low / Informational | R5 / Low / Informational | PASS |
| controlled-failure | R6 / insufficient_evidence / Insufficient evidence | R6 / insufficient_evidence / Insufficient evidence | PASS |

## Evidence review

Machine checks verify evidence IDs, tool-call correlation, policy values and allowed synthesis IDs. A group member must still verify the source passages, technical applicability and business-impact judgment.

## Required checks

Applicability change: positive to patched. Impact change: positive to medium. Missing/conflicting evidence: two subcases. Controlled failure: both threat lookups unavailable with no fallback. Exposure change additionally verifies Critical versus High priority.

## Limitations

- Controlled fixtures are not broad accuracy evaluation.
- Replay is scripted, not an LLM run.
- Live Duke demonstration and actual group evidence review are separate requirements.
