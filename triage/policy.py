import re

VERSION = "2.0"
FIELDS = (
    "product_match", "version_affected", "ssl_vpn_enabled",
    "attack_path", "internet_reachable", "impact",
)


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        return None
    return tuple(int(v) for v in value.split("."))


def affected_version(value, ranges):
    version = version_tuple(value)
    if version is None:
        return None
    covered = False
    for record in ranges:
        start = version_tuple(record.get("version"))
        end = version_tuple(record.get("lessThanOrEqual"))
        if record.get("status") != "affected" or start is None or end is None:
            continue
        if version[:2] != start[:2] or start[:2] != end[:2]:
            continue
        covered = True
        if start <= version <= end:
            return True
    # Keeping unlisted firmware branches unknown.
    return False if covered else None


def decision(rule, rating=None, priority="Insufficient evidence", status="insufficient_evidence", reason=""):
    return {
        "policy_version": VERSION, "policy_rule": rule, "rating": rating,
        "priority": priority, "status": status, "rationale": reason,
    }


def apply(facts):
    if set(facts) != set(FIELDS):
        return decision(None, priority="Review", status="review_required", reason="Invalid policy input fields.")
    for field in FIELDS:
        value = facts[field]
        allowed = (None, "conflicting", True, False)
        if field == "impact":
            allowed = (None, "conflicting", "High", "Medium", "Low")
        if not any(type(value) is type(v) and value == v for v in allowed):
            return decision(None, priority="Review", status="review_required", reason="Invalid policy input type.")
    if facts["internet_reachable"] is True and facts["attack_path"] is False:
        return decision(None, priority="Review", status="review_required", reason="Contradictory attack-path inputs.")
    # Checking absent prerequisites before unrelated evidence gaps.
    prerequisites = ("product_match", "version_affected", "ssl_vpn_enabled", "attack_path")
    for field in prerequisites:
        if facts[field] is False:
            return decision("R5", "Low", "Informational", "rated", f"Decisive prerequisite absent: {field}.")
    if "conflicting" in facts.values():
        return decision("R6", priority="Review", status="review_required", reason="Unresolved decisive evidence conflict.")
    missing = [field for field in (*prerequisites, "impact") if facts[field] is None]
    if facts["impact"] == "High" and facts["internet_reachable"] is None:
        missing.append("internet_reachable")
    if missing:
        return decision("R6", reason="Missing decisive evidence: " + ", ".join(missing) + ".")
    if facts["impact"] == "High":
        if facts["internet_reachable"] is True:
            return decision("R1", "High", "Critical", "rated", "Applicable Internet-reachable service with major business consequences.")
        return decision("R2", "High", "High", "rated", "Applicable service with a supported internal path, major consequences, and no Internet reachability.")
    if facts["impact"] == "Medium":
        return decision("R3", "Medium", "Medium", "rated", "Applicable supported attack path with limited business consequences.")
    return decision("R4", "Low", "Low", "rated", "Applicable supported attack path with minor consequences in an isolated low-value service.")
