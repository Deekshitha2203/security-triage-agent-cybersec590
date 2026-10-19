from triage.agent import run
from triage.common import ROOT, now, write_json, write_text

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


def evaluate():
    # Saving expected results before running the cases.
    out = ROOT / "artifacts/testing"
    write_json(out / "expected_results.json", {"created_at": now(), "source": "R1-R6 policy",
               "model_mode": "scripted_replay", "cases": [{"case": name, "scenario": scenario, "failure": failure,
                    "expected": dict(zip(("rule", "rating", "priority", "status"), expected))} for name, scenario, failure, expected in CASES]})
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
    passed = sum(r["pass"] for r in results)
    summary = {"generated_at": now(), "policy_version": "2.0", "passed": passed, "total": len(results),
               "model_mode": "scripted_replay", "group_consensus_review": "pending", "cases": results,
               "limitations": ["The tests cover eleven controlled scenarios.", "Replay uses scripted responses.",
                               "Live model runs and evidence reviews are recorded separately."]}
    write_json(out / "results.json", summary)
    lines = ["# Testing results", "", f"**Actual controlled results:** {passed}/{len(results)} passed.", "",
             "Expected outcomes were saved before execution. Tests use scripted replay and verified cached public evidence; local scenario facts are simulated.",
             "Group evidence review is recorded separately.", "",
             "| Case | Expected rule / rating / priority | Actual rule / rating / priority | Result |", "| --- | --- | --- | --- |"]
    for r in results:
        fmt = lambda d: f"{d['rule']} / {d['rating'] or d['status']} / {d['priority']}"
        lines.append(f"| {r['case']} | {fmt(r['expected'])} | {fmt(r['actual'])} | {'PASS' if r['pass'] else 'FAIL'} |")
    lines += ["", "## Evidence review", "", "Machine checks verify evidence IDs, tool-call correlation, policy values and allowed synthesis IDs. A group member must still verify the source passages, technical applicability and business-impact judgment.",
              "", "## Required checks", "", "Applicability change: positive to patched. Impact change: positive to medium. Missing/conflicting evidence: two subcases. Controlled failure: both threat lookups unavailable with no fallback. Exposure change additionally verifies Critical versus High priority.",
              "", "## Limitations", ""] + ["- " + s for s in summary["limitations"]]
    write_text(out / "TESTING_REPORT.md", "\n".join(lines) + "\n")
    print(f"Replay tests: {passed}/{len(results)} passed.")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    evaluate()
