"""Fixed-source tools with attributed evidence and guarded dispatch."""
from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time

from .common import ROOT, CVE, Budget, SafeError, digest, http, now, read_json, write_json

SOURCES = {
    "cna": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/21xxx/CVE-2024-21762.json",
    "cert": "https://cert.europa.eu/publications/security-advisories/2024-018/",
    "kev": "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
}
SOURCE_FILES = {"cna": "cna.json", "cert": "cert.html", "kev": "kev.json"}


def tool_spec(name, description, properties):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}}}


def tool_definitions(snapshot_id):
    return [tool_spec("lookup_environment", "Read the selected simulated environment. Preserve unknowns and source locators.",
                      {"asset_id": {"type": "string", "enum": ["N02"]}, "snapshot_id": {"type": "string", "enum": [snapshot_id]}}),
            tool_spec("lookup_vulnerability", "Read authoritative affected FortiOS versions (cna) or SSL-VPN prerequisite (cert).",
                      {"cve_id": {"type": "string", "enum": [CVE]}, "source": {"type": "string", "enum": ["cna", "cert"]}}),
            tool_spec("lookup_kev", "Read reported exploitation context. A miss or error does not establish safety.",
                      {"cve_id": {"type": "string", "enum": [CVE]}})]


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def cert_passage(raw):
    parser = PlainText()
    parser.feed(raw.decode())
    text = re.sub(r"\s+", " ", " ".join(parser.parts))
    start = text.find("The vulnerability CVE-2024-21762")
    end = text.find("The vulnerability CVE-2024-23113", start)
    if start < 0 or end < 0 or "SSL-VPN" not in text[start:end]:
        raise SafeError("advisory_component_not_verified")
    return text[start:end].strip()


def normalize(source, raw, meta, mode, artifact):
    base = {"publisher": {"cna": "Fortinet CNA via official CVE list", "cert": "CERT-EU", "kev": "CISA"}[source],
            "source": SOURCES[source], "source_mode": mode, "retrieved_at": meta["retrieved_at"],
            "used_at": now(), "source_sha256": meta.get("source_sha256", digest(raw)),
            "saved_sha256": digest(raw), "saved_artifact": artifact, "fallback_reason": meta.get("fallback_reason")}
    if source == "cna":
        data = json.loads(raw)
        if data["cveMetadata"]["cveId"] != CVE:
            raise SafeError("wrong_threat_record")
        cna = data["containers"]["cna"]
        products = [(i, p) for i, p in enumerate(cna["affected"]) if p["product"] == "FortiOS"]
        if len(products) != 1:
            raise SafeError("ambiguous_product_record")
        index, product = products[0]
        eid = "THREAT-CNA"
        evidence = {**base, "evidence_id": eid, "locator": f"/containers/cna/affected/{index}",
                    "source_date": data["cveMetadata"].get("dateUpdated"),
                    "published_at": data["cveMetadata"].get("datePublished"),
                    "quote": product, "solutions": cna.get("solutions", []), "metrics": cna.get("metrics", [])}
        return {"cve_id": CVE, "product": "FortiOS", "affected_ranges": product["versions"], "evidence": [evidence]}
    if source == "cert":
        evidence = {**base, "evidence_id": "THREAT-COMPONENT", "locator": "Technical Details; paragraph beginning The vulnerability CVE-2024-21762",
                    "source_date": "2024-02-09", "quote": cert_passage(raw)}
        return {"cve_id": CVE, "affected_component": "SSL-VPN", "unauthenticated": True, "evidence": [evidence]}
    data = json.loads(raw)
    matches = [(i, v) for i, v in enumerate(data["vulnerabilities"]) if v["cveID"] == CVE]
    if len(matches) > 1:
        raise SafeError("duplicate_kev_record")
    entry = matches[0][1] if matches else None
    locator = meta.get("original_locator") or (f"/vulnerabilities/{matches[0][0]}" if matches else "/vulnerabilities")
    evidence = {**base, "evidence_id": "THREAT-KEV", "locator": locator,
                "source_date": data.get("dateReleased"), "quote": entry,
                "catalog_version": data.get("catalogVersion"), "lookup_scope": "CVE ID in fetched catalog"}
    return {"cve_id": CVE, "known_exploited": bool(entry), "entry": entry, "evidence": [evidence]}


class Tools:
    def __init__(self, snapshot, budget, output, mode="cached", controlled_failure=None):
        self.snapshot = snapshot
        self.budget = budget
        self.output = Path(output)
        self.mode = mode
        self.controlled_failure = controlled_failure
        self.trace = []
        self.successful = {}
        self.seen = set()
        self.invalid = 0
        self.last_attempts = []

    def source(self, source):
        path = ROOT / "data/evidence" / SOURCE_FILES[source]
        meta_path = ROOT / "data/evidence" / (source + ".meta.json")
        attempts = []
        self.last_attempts = attempts
        if self.mode != "cached":
            for attempt in range(2):
                if attempt:
                    self.budget.use_tool()
                try:
                    raw = http(SOURCES[source], self.budget.timeout(self.budget.config["http_timeout_seconds"]))
                    parsed_meta = {"retrieved_at": now(), "source_sha256": digest(raw)}
                    # Validate semantics before treating a live payload as evidence.
                    normalize(source, raw, parsed_meta, "live", "pending")
                    attempts.append({"attempt": attempt + 1, "status": "ok", "time": now()})
                    return raw, parsed_meta, "live", attempts
                except SafeError as exc:
                    attempts.append({"attempt": attempt + 1, "status": "error", "error_code": str(exc), "time": now()})
                except (ValueError, KeyError, TypeError):
                    attempts.append({"attempt": attempt + 1, "status": "error", "error_code": "invalid_source_payload", "time": now()})
                if attempt == 0:
                    delay = min(0.2, max(0, self.budget.remaining()))
                    time.sleep(delay)
            if self.mode == "live":
                raise SafeError("live_lookup_failed")
        if not path.exists() or not meta_path.exists():
            raise SafeError("verified_cache_unavailable")
        raw, meta = path.read_bytes(), read_json(meta_path)
        if digest(raw) != meta["saved_sha256"] or meta["source"] != SOURCES[source]:
            raise SafeError("cache_integrity_failed")
        if attempts:
            meta = {**meta, "fallback_reason": attempts}
        return raw, meta, "cached", attempts

    def execute(self, call):
        start = now()
        call_id = call.get("id", "invalid-call")
        function = call.get("function", {})
        name, arguments = function.get("name"), function.get("arguments")
        result = {"tool_call_id": call_id, "tool": name, "status": "error", "time": start}
        self.last_attempts = []
        try:
            if isinstance(arguments, str):
                arguments = json.loads(arguments)
            definitions = {d["function"]["name"]: d["function"]["parameters"] for d in tool_definitions(self.snapshot["snapshot_id"])}
            if name not in definitions or not isinstance(arguments, dict):
                raise SafeError("invalid_tool_request")
            schema = definitions[name]
            if set(arguments) != set(schema["required"]):
                raise SafeError("invalid_tool_arguments")
            if any(arguments[k] not in v["enum"] for k, v in schema["properties"].items() if k in {"asset_id", "snapshot_id", "cve_id"}):
                raise SafeError("scope_mismatch")
            if any(arguments[k] not in v["enum"] for k, v in schema["properties"].items()):
                raise SafeError("invalid_tool_arguments")
            fingerprint = json.dumps([name, arguments], sort_keys=True)
            if fingerprint in self.seen:
                raise SafeError("duplicate_query_no_new_evidence")
            self.seen.add(fingerprint)
            self.budget.use_tool()
            if self.controlled_failure == "threat_unavailable" and name == "lookup_vulnerability":
                # The synthetic failure uses two attempts and forbids fallback by construction.
                self.budget.use_tool()
                result["attempts"] = [{"attempt": 1, "status": "error", "error_code": "simulated_timeout"},
                                      {"attempt": 2, "status": "error", "error_code": "simulated_timeout"}]
                raise SafeError("controlled_threat_lookup_unavailable_no_cache")
            if name == "lookup_environment":
                facts = self.snapshot["facts"]
                if self.snapshot.get("asset_id") != "N02" or self.snapshot.get("source_mode") != "simulated":
                    raise SafeError("environment_scope_or_mode_mismatch")
                expected_fields = {"product", "firmware", "ssl_vpn_enabled", "attack_path", "internet_reachable", "impact"}
                if set(facts) != expected_fields:
                    raise SafeError("invalid_environment_schema")
                ids = {e["evidence_id"] for e in self.snapshot["evidence"]}
                if any(not f.get("evidence_ids") or not set(f["evidence_ids"]) <= ids for f in facts.values()):
                    raise SafeError("environment_evidence_missing")
                if any(e.get("source_mode") != "simulated" for e in self.snapshot["evidence"]):
                    raise SafeError("environment_evidence_mode_mismatch")
                data = {k: self.snapshot[k] for k in ["asset_id", "snapshot_id", "assessment_scope", "facts", "evidence", "assumptions", "limitations", "overrides", "source_mode"]}
            else:
                source = "kev" if name == "lookup_kev" else arguments["source"]
                raw, meta, mode, attempts = self.source(source)
                if source == "kev":
                    # Persist only this CVE's public entry, not unrelated catalog text.
                    catalog = json.loads(raw)
                    selected = [(i, v) for i, v in enumerate(catalog["vulnerabilities"]) if v["cveID"] == CVE]
                    meta = {**meta, "original_locator": meta.get("original_locator") or (f"/vulnerabilities/{selected[0][0]}" if selected else "/vulnerabilities"),
                            "source_sha256": meta.get("source_sha256", digest(raw))}
                    if mode == "live":
                        excerpt = {k: v for k, v in catalog.items() if k != "vulnerabilities"}
                        excerpt["vulnerabilities"] = [v for _, v in selected]
                        raw = (json.dumps(excerpt, indent=2) + "\n").encode()
                artifact_path = self.output / "evidence" / SOURCE_FILES[source]
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                # Public payloads contain no provider credentials. Block any known secret before saving.
                from .common import redact
                clean_raw = redact(raw.decode()).encode()
                if clean_raw != raw:
                    raise SafeError("credential_in_source_payload")
                artifact_path.write_bytes(raw)
                data = normalize(source, raw, meta, mode, "evidence/" + SOURCE_FILES[source])
                result["attempts"] = attempts
            result.update(status="ok", arguments=arguments, data=data)
            key = name if name != "lookup_vulnerability" else name + ":" + arguments["source"]
            self.successful[key] = result
        except SafeError as exc:
            result["error_code"] = str(exc)
            if str(exc).startswith("invalid"):
                self.invalid += 1
        except (ValueError, KeyError, TypeError, OSError):
            result["error_code"] = "invalid_tool_payload"
            self.invalid += 1
        result["completed_at"] = now()
        if self.last_attempts and "attempts" not in result:
            result["attempts"] = self.last_attempts
        self.trace.append(result)
        write_json(self.output / "tool_trace.json", self.trace)
        return result
