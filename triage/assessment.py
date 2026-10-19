import json

from .common import CVE, now
from .policy import FIELDS, apply, affected_version, decision


def build(tools, snapshot, stop_reason=None):
    results = tools.successful
    env = results.get("lookup_environment", {}).get("data")
    cna = results.get("lookup_vulnerability:cna", {}).get("data")
    cert = results.get("lookup_vulnerability:cert", {}).get("data")
    kev = results.get("lookup_kev", {}).get("data")
    facts = dict.fromkeys(FIELDS)
    refs = {field: [] for field in FIELDS}
    evidence = []
    for record in (env, cna, cert, kev):
        if record:
            evidence.extend(record.get("evidence", []))
    if env:
        local = env["facts"]
        if cna:
            product = local["product"]["value"]
            if product is None or product == "conflicting":
                facts["product_match"] = product
            else:
                facts["product_match"] = product == cna["product"]
            refs["product_match"] = local["product"]["evidence_ids"] + ["THREAT-CNA"]
            firmware = local["firmware"]["value"]
            facts["version_affected"] = "conflicting" if firmware == "conflicting" else affected_version(firmware, cna["affected_ranges"])
            refs["version_affected"] = local["firmware"]["evidence_ids"] + ["THREAT-CNA"]
        # Using local VPN settings only after confirming the affected component.
        if cert and cert.get("affected_component") == "SSL-VPN":
            for field in ("ssl_vpn_enabled", "attack_path", "internet_reachable"):
                facts[field] = local[field]["value"]
                refs[field] = local[field]["evidence_ids"] + ["THREAT-COMPONENT"]
        facts["impact"] = local["impact"]["value"]
        refs["impact"] = local["impact"]["evidence_ids"]
    result = apply(facts)
    if stop_reason:
        result = decision(None, priority="Review", status="review_required", reason="Execution could not complete: " + stop_reason)
    if facts["internet_reachable"] is True and facts["attack_path"] is False:
        result = decision(None, priority="Review", status="review_required", reason="Contradictory path inputs require validation review.")
    if any(facts[field] is not None and not refs[field] for field in facts):
        result = decision(None, priority="Review", status="review_required", reason="A decisive input lacks attributed evidence.")
    unknowns = [k for k, v in facts.items() if v is None]
    conflicts = [k for k, v in facts.items() if v == "conflicting"]
    if env and env["facts"]["firmware"]["value"] is None:
        unknowns.append("exact_firmware_version")
    evidence_ids = sorted({eid for ids in refs.values() for eid in ids})
    claims = {"C-POLICY": {"text": result["rationale"], "evidence_ids": evidence_ids}}
    if env:
        claims["C-SCOPE"] = {"text": env["assessment_scope"] + "; all local evidence is simulated.", "evidence_ids": ["ENV-ASSET"]}
    if facts["version_affected"] is not None:
        claims["C-VERSION"] = {
            "text": f"Affected-version comparison: {facts['version_affected']}.",
            "evidence_ids": refs["version_affected"],
        }
    if facts["impact"] is not None:
        claims["C-IMPACT"] = {
            "text": f"Business impact: {facts['impact']}, based on the cited business context. Local compromise is unconfirmed.",
            "evidence_ids": refs["impact"],
        }
    if unknowns or conflicts:
        claims["C-GAPS"] = {
            "text": f"Unknowns: {', '.join(unknowns) or 'none'}; conflicts: {', '.join(conflicts) or 'none'}.",
            "evidence_ids": evidence_ids,
        }
    if kev:
        claims["C-KEV"] = {
            "text": ("CISA reports known exploitation. Local compromise is unconfirmed."
                     if kev["known_exploited"] else "No CISA match in the source scope. Safety remains unconfirmed."),
            "evidence_ids": ["THREAT-KEV"],
        }
    actions = {}
    if result["policy_rule"] == "R5":
        actions["A-RETAIN"] = {
            "text": "Keep evidence of the absent prerequisite. Reassess after firmware, component, or route changes. Low applies only to this CVE.",
            "owner": "VPN owner", "urgency": "Informational", "evidence_ids": evidence_ids,
        }
        if facts["version_affected"] is True:
            actions["A-PATCH-LATENT"] = {
                "text": "Plan a firmware upgrade despite the absent component or attack path.",
                "owner": "VPN owner", "urgency": "Planned maintenance",
                "evidence_ids": refs["version_affected"],
            }
    elif result["status"] != "rated":
        actions["A-RESOLVE"] = {
            "text": "Get dated firmware and SSL-VPN configuration evidence for each gateway. Verify the endpoint and attack path, and resolve conflicts before reassessing.",
            "owner": "VPN owner and SOC analyst",
            "urgency": "Prompt evidence resolution" if kev and kev["known_exploited"] else "Evidence resolution",
            "evidence_ids": evidence_ids,
        }
    else:
        actions["A-PATCH"] = {
            "text": "Follow the vendor upgrade path to a supported release fixed for this CVE. Coordinate failover and change approval. Version 7.2.7 is a test boundary only.",
            "owner": "VPN owner", "urgency": result["priority"], "evidence_ids": ["THREAT-CNA"],
        }
        if result["rating"] == "High":
            actions["A-LOGS"] = {
                "text": "Review VPN, firewall, and identity logs. Escalate suspicious findings to incident response; local compromise is unconfirmed.",
                "owner": "SOC analyst", "urgency": result["priority"],
                "evidence_ids": ["S04", "THREAT-KEV"] if kev else ["S04"],
            }
    if stop_reason:
        actions["A-RERUN"] = {
            "text": "Fix the execution failure and rerun with a real model for the live demonstration.",
            "owner": "Project group", "urgency": "Before submission", "evidence_ids": [],
        }

    applicability_facts = [facts[field] for field in ("product_match", "version_affected", "ssl_vpn_enabled")]
    if any(value is False for value in applicability_facts):
        applicability = "not_applicable"
    elif "conflicting" in applicability_facts:
        applicability = "conflicting"
    elif all(value is True for value in applicability_facts):
        applicability = "confirmed"
    else:
        applicability = "unknown"

    return {
        "threat_id": CVE, "asset_id": "N02", "assessed_at": now(), **result,
        "snapshot_id": snapshot["snapshot_id"], "scenario": snapshot["scenario"],
        "assessment_scope": snapshot["assessment_scope"], "applicability": applicability,
        "policy_inputs": {field: {"value": value, "evidence_ids": refs[field]} for field, value in facts.items()},
        "evidence": evidence, "unknowns": unknowns, "conflicts": conflicts,
        "assumptions": env["assumptions"] if env else [], "limitations": snapshot["limitations"],
        "confidence": {
            "level": "limited" if result["status"] != "rated" else "moderate",
            "reason": "Simulated environment; human review pending. Confidence is qualitative.",
        },
        "exploitation_context": "known_exploited" if kev and kev["known_exploited"] else "no_match_in_catalog" if kev else "unknown",
        "human_review": {"status": "pending", "reviewer": None, "reviewed_at": None},
        "claims": claims, "recommended_actions": actions, "stop_reason": stop_reason,
        "evidence_needed_to_change_decision": "Dated firmware, component, route, and business-dependency evidence for this scope. Reassess after configuration changes or conflict resolution.",
    }


def validate_synthesis(content, assessment):
    try:
        draft = json.loads(content)
    except (ValueError, TypeError):
        return None
    keys = {"policy_rule", "rating", "priority", "claim_ids", "action_ids"}
    if not isinstance(draft, dict) or set(draft) != keys:
        return None
    if any(draft[k] != assessment[k] for k in ("policy_rule", "rating", "priority")):
        return None
    # Accepting only registered claims and actions with saved evidence.
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
    if set(draft["action_ids"]) != set(assessment["recommended_actions"]):
        return None
    return draft
