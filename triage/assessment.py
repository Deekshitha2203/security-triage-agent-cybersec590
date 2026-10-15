"""Evidence-grounded policy inputs and constrained claims/actions for synthesis."""
from __future__ import annotations

from .common import CVE, now
from .policy import apply, affected_version, decision


def build(tools, snapshot, stop_reason=None):
    results = tools.successful
    env = results.get("lookup_environment", {}).get("data")
    cna = results.get("lookup_vulnerability:cna", {}).get("data")
    cert = results.get("lookup_vulnerability:cert", {}).get("data")
    kev = results.get("lookup_kev", {}).get("data")
    facts = dict.fromkeys(("product_match", "version_affected", "ssl_vpn_enabled", "attack_path", "internet_reachable", "impact"))
    refs = {k: [] for k in facts}
    evidence = []
    for record in (env, cna, cert, kev):
        if record:
            evidence.extend(record.get("evidence", []))
    if env:
        local = env["facts"]
        if cna:
            product = local["product"]["value"]
            facts["product_match"] = "conflicting" if product == "conflicting" else None if product is None else product == cna["product"]
            refs["product_match"] = local["product"]["evidence_ids"] + ["THREAT-CNA"]
            firmware = local["firmware"]["value"]
            facts["version_affected"] = "conflicting" if firmware == "conflicting" else affected_version(firmware, cna["affected_ranges"])
            refs["version_affected"] = local["firmware"]["evidence_ids"] + ["THREAT-CNA"]
        # SSL-VPN-specific prerequisites require a successful component lookup.
        if cert and cert.get("affected_component") == "SSL-VPN":
            for field in ("ssl_vpn_enabled", "attack_path", "internet_reachable"):
                facts[field] = local[field]["value"]
                refs[field] = local[field]["evidence_ids"] + ["THREAT-COMPONENT"]
        facts["impact"] = local["impact"]["value"]
        refs["impact"] = local["impact"]["evidence_ids"]
    d = apply(facts)
    if stop_reason:
        d = decision(None, priority="Review", status="review_required", reason="Execution could not complete: " + stop_reason)
    # Cross-field contradictions are validation errors, not evidence of safety.
    if facts["internet_reachable"] is True and facts["attack_path"] is False:
        d = decision(None, priority="Review", status="review_required", reason="Contradictory path inputs require validation review.")
    if any(facts[k] is not None and not refs[k] for k in facts):
        d = decision(None, priority="Review", status="review_required", reason="A decisive input lacks attributed evidence.")
    unknowns = [k for k, v in facts.items() if v is None]
    conflicts = [k for k, v in facts.items() if v == "conflicting"]
    if env and env["facts"]["firmware"]["value"] is None:
        unknowns.append("exact_firmware_version")
    claims = {
        "C-POLICY": {"text": d["rationale"], "evidence_ids": sorted({eid for ids in refs.values() for eid in ids})},
    }
    if env:
        claims["C-SCOPE"] = {"text": env["assessment_scope"] + "; all local evidence is simulated.", "evidence_ids": ["ENV-ASSET"]}
    if facts["version_affected"] is not None:
        claims["C-VERSION"] = {"text": f"Affected-version comparison: {facts['version_affected']}; exact input and source ranges are preserved.", "evidence_ids": refs["version_affected"]}
    if facts["impact"] is not None:
        claims["C-IMPACT"] = {"text": f"Business impact is {facts['impact']}; this is a policy interpretation of the cited business context, not observed compromise.", "evidence_ids": refs["impact"]}
    if unknowns or conflicts:
        claims["C-GAPS"] = {"text": "Unknowns: " + ", ".join(unknowns) + "; conflicts: " + (", ".join(conflicts) or "none") + ".", "evidence_ids": sorted({eid for ids in refs.values() for eid in ids})}
    if kev:
        claims["C-KEV"] = {"text": "CISA catalog lookup " + ("reports known exploitation; it does not establish local compromise." if kev["known_exploited"] else "found no match within the source scope; this does not establish safety."), "evidence_ids": ["THREAT-KEV"]}
    actions = {}
    if d["policy_rule"] == "R5":
        actions["A-RETAIN"] = {"text": "Retain the evidence for the absent prerequisite and reassess after firmware, component, or route changes. Low is scoped to this CVE.", "owner": "VPN owner", "urgency": "Informational", "evidence_ids": claims["C-POLICY"]["evidence_ids"]}
        if facts["version_affected"] is True:
            actions["A-PATCH-LATENT"] = {"text": "Plan upgrade of the affected firmware even though a necessary exposure/component prerequisite is absent.", "owner": "VPN owner", "urgency": "Planned maintenance", "evidence_ids": refs["version_affected"]}
    elif d["status"] != "rated":
        actions["A-RESOLVE"] = {"text": "Obtain dated firmware and SSL-VPN configuration evidence for each assessed gateway, verify the affected endpoint and attack path, and reconcile decisive conflicts before reassessment.", "owner": "VPN owner and SOC analyst", "urgency": "Prompt evidence resolution" if kev and kev["known_exploited"] else "Evidence resolution", "evidence_ids": claims["C-POLICY"]["evidence_ids"]}
    else:
        actions["A-PATCH"] = {"text": "Upgrade through the vendor-supported path to a currently supported release fixed for this CVE; coordinate gateway failover and change approval. Historical test version 7.2.7 is not a current deployment recommendation.", "owner": "VPN owner", "urgency": d["priority"], "evidence_ids": ["THREAT-CNA"]}
        if d["rating"] == "High":
            actions["A-LOGS"] = {"text": "Review retained VPN, firewall and identity logs for suspicious activity; escalate actual findings to incident response. No compromise is asserted by this assessment.", "owner": "SOC analyst", "urgency": d["priority"], "evidence_ids": ["S04", "THREAT-KEV"] if kev else ["S04"]}
    if stop_reason:
        actions["A-RERUN"] = {"text": "Resolve the recorded execution failure and rerun the real model workflow; a replay does not satisfy the live demonstration requirement.", "owner": "Project group", "urgency": "Before submission", "evidence_ids": []}
    assessment = {"threat_id": CVE, "asset_id": "N02", "assessed_at": now(), **d,
                  "snapshot_id": snapshot["snapshot_id"], "scenario": snapshot["scenario"], "assessment_scope": snapshot["assessment_scope"],
                  "applicability": "not_applicable" if any(facts[k] is False for k in ("product_match", "version_affected", "ssl_vpn_enabled")) else "conflicting" if any(facts[k] == "conflicting" for k in ("product_match", "version_affected", "ssl_vpn_enabled")) else "confirmed" if all(facts[k] is True for k in ("product_match", "version_affected", "ssl_vpn_enabled")) else "unknown",
                  "policy_inputs": {k: {"value": v, "evidence_ids": refs[k]} for k, v in facts.items()},
                  "evidence": evidence, "unknowns": unknowns, "conflicts": conflicts,
                  "assumptions": env["assumptions"] if env else [], "limitations": snapshot["limitations"],
                  "confidence": {"level": "limited" if d["status"] != "rated" else "moderate",
                                 "reason": "Synthetic environment and pending human review; confidence is not a numeric probability."},
                  "exploitation_context": "known_exploited" if kev and kev["known_exploited"] else "no_match_in_catalog" if kev else "unknown",
                  "human_review": {"status": "pending", "reviewer": None, "reviewed_at": None},
                  "claims": claims, "recommended_actions": actions, "stop_reason": stop_reason,
                  "evidence_needed_to_change_decision": "Dated firmware, component state, supported route/exposure, and business-dependency evidence for the assessed scope; version/configuration changes or reconciled contradictions trigger reassessment."}
    return assessment


def validate_synthesis(content, assessment):
    """The model selects supported claim/action IDs; arbitrary assertions cannot enter reports."""
    import json
    try:
        draft = json.loads(content)
    except (ValueError, TypeError):
        return None
    keys = {"policy_rule", "rating", "priority", "claim_ids", "action_ids"}
    if set(draft) != keys:
        return None
    if any(draft[k] != assessment[k] for k in ("policy_rule", "rating", "priority")):
        return None
    for field, registry in [("claim_ids", assessment["claims"]), ("action_ids", assessment["recommended_actions"])]:
        items = draft[field]
        if not isinstance(items, list) or not items or any(not isinstance(i, str) or i not in registry for i in items):
            return None
        if len(set(items)) != len(items):
            return None
    if "C-POLICY" not in draft["claim_ids"]:
        return None
    if (assessment["unknowns"] or assessment["conflicts"]) and "C-GAPS" not in draft["claim_ids"]:
        return None
    ids = {e["evidence_id"] for e in assessment["evidence"]}
    selected = [assessment["claims"][i] for i in draft["claim_ids"]] + [assessment["recommended_actions"][i] for i in draft["action_ids"]]
    if any(not set(c["evidence_ids"]) <= ids for c in selected):
        return None
    if not set(assessment["recommended_actions"]) <= set(draft["action_ids"]):
        return None
    return draft
