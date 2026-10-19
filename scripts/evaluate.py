from triage.agent import run
from triage.common import ROOT, now, write_json, write_text
# runs all the test scenarios and saves expected vs actual results

# each case is a tuple of (case name, scenario file, failure to simulate, expected (rule, rating, priority, status))
CASES = [
    ("baseline", "baseline", None, ("R6", None, "Insufficient evidence", "insufficient_evidence")),
    ("positive", "positive", None, ("R1", "High", "Critical", "rated")),
    ("applicability-change", "patched", None, ("R5", "Low", "Informational", "rated")),
    ("exposure-change", "internal", None, ("R2", "High", "High", "rated")),
    ("impact-change", "medium", None, ("R3", "Medium", "Medium", "rated")),
    ("low-impact", "low", None, ("R4", "Low", "Low", "rated")),
    ("missing-evidence", "missing", None, ("R6", None, "Insufficient evidence", "insufficient_evidence")),
    ("conflicting-evidence", "conflicting", None, ("R6", None, "Review", "review_required")),
    ("missing-exposure", "unknown-exposure", None, ("R6", None, "Insufficient evidence", "insufficient_evidence")),
    ("disabled-component", "disabled", None, ("R5", "Low", "Informational", "rated")),
    ("controlled-failure", "positive", "threat_unavailable", ("R6", None, "Insufficient evidence", "insufficient_evidence")),
]

def evaluate():  # runs every case, compares it with what we expected, and writes the results and the testing report

    out = ROOT / "artifacts/testing"
    write_json(out / "expected_results.json", {"created_at": now(), "source": "approved documented policy; human consensus signoff pending",
               "model_mode": "scripted_replay", "cases": [{"case": name, "scenario": scenario, "failure": failure,
                    "expected": dict(zip(("rule", "rating", "priority", "status"), expected))} for name, scenario, failure, expected in CASES]})
    # run each case and check the actual result against the expected one
    results = []
    for name, scenario, failure, expected in CASES:
        assessment, checklist = run(ROOT / f"data/environment/{scenario}.json", out / "runs" / name,
                                    provider="replay", evidence_mode="cached", controlled_failure=failure)
        actual = tuple(assessment[k] for k in ("policy_rule", "rating", "priority", "status"))
        machine_audit = all(checklist["checks"][k] for k in ("selected_snapshot_loaded", "results_returned_with_call_ids", "policy_and_citations_checked", "checked_model_synthesis"))
        if failure:
            machine_audit = machine_audit and bool(assessment["tool_errors"]) and all(assessment["policy_inputs"][k]["value"] is None for k in ("version_affected", "ssl_vpn_enabled"))
        results.append({"case": name, "expected": dict(zip(("rule", "rating", "priority", "status"), expected)),
                        "actual": dict(zip(("rule", "rating", "priority", "status"), actual)),
                        "pass": expected == actual and machine_audit, "attributed_evidence_audit": machine_audit,
                        "run": f"runs/{name}", "model_mode": "scripted_replay", "human_consensus": "pending"})
    # save all results as json
    passed = sum(r["pass"] for r in results)
    summary = {"generated_at": now(), "policy_version": "2.0", "passed": passed, "total": len(results),
               "model_mode": "scripted_replay", "group_consensus_review": "pending", "cases": results,
               "limitations": ["Controlled fixtures are not broad accuracy evaluation.", "Replay is scripted, not an LLM run.",
                               "Live Duke demonstration and actual group evidence review are separate requirements."]}
    write_json(out / "results.json", summary)
    # write the testing report as a markdown table
    lines = ["# Testing results", "", f"**Actual controlled results:** {passed}/{len(results)} passed.", "",
             "Expected outcomes were saved before execution. Tests use scripted replay and verified cached public evidence; local scenario facts are simulated.",
             "No expert/group consensus, real model performance, or completed human review is claimed.", "",
             "| Case | Expected rule / rating / priority | Actual rule / rating / priority | Result |", "| --- | --- | --- | --- |"]
    for r in results:
        fmt = lambda d: f"{d['rule']} / {d['rating'] or d['status']} / {d['priority']}"
        lines.append(f"| {r['case']} | {fmt(r['expected'])} | {fmt(r['actual'])} | {'PASS' if r['pass'] else 'FAIL'} |")
    lines += ["", "## Evidence review", "", "Machine checks verify evidence IDs, tool-call correlation, policy values and allowed synthesis IDs. A group member must still verify the source passages, technical applicability and business-impact judgment.",
              "", "## Required checks", "", "Applicability change: positive to patched. Impact change: positive to medium. Missing/conflicting evidence: two subcases. Controlled failure: both threat lookups unavailable with no fallback. Exposure change additionally verifies Critical versus High priority.",
              "", "## Limitations", ""] + ["- " + s for s in summary["limitations"]]
    write_text(out / "TESTING_REPORT.md", "\n".join(lines) + "\n")
    print(f"Controlled replay cases: {passed}/{len(results)} passed; human consensus and real-model demonstration are tracked separately.")
    # exit with an error if any case failed
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    evaluate()
