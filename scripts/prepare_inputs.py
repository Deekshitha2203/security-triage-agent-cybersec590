"""Derive a scoped snapshot from the supplied DOCX and create labeled test variants."""
from copy import deepcopy
import json
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET

from triage.common import ROOT, CVE, digest, now, write_json

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def prepare():
    source = ROOT / "Windows_Enterprise_Environment.docx"
    with ZipFile(source) as z:
        doc = ET.fromstring(z.read("word/document.xml"))
    paragraph_text = ["".join(t.text or "" for t in p.findall(".//w:t", NS))
                      for p in doc.findall(".//w:body/w:p", NS)]
    rows = [["".join(t.text or "" for t in cell.findall(".//w:t", NS))
             for cell in row.findall("w:tc", NS)] for row in doc.findall(".//w:tr", NS)]

    def row(prefix):
        return " | ".join(next(r for r in rows if r and r[0].startswith(prefix)))

    def paragraph(substring):
        return next(p for p in paragraph_text if substring in p)

    passages = {
        "ENV-ASSET": ("Endpoints appliances and cloud services; infrastructure table; N02 row", row("N02")),
        "ENV-NETWORK": ("Network architecture and access; public services paragraph", paragraph("Public services use documentation addresses")),
        "ENV-ORGANIZATION": ("Organization and scope; opening paragraph", paragraph("Northbridge Services has 1,000 staff")),
        "S02": ("Evidence controls table; S02 row", row("S02")),
        "S04": ("Evidence controls table; S04 row", row("S04")),
        "S05": ("Evidence controls table; S05 row", row("S05")),
        "ENV-UNKNOWN": ("Endpoints appliances and cloud services; additional devices paragraph", paragraph("Appliance firmware and precise patch builds are unknown"))
    }
    evidence = [{"evidence_id": eid, "publisher": "Course fictional environment",
                 "source": source.name, "locator": locator, "quote": quote,
                 "source_mode": "simulated", "source_date": None, "retrieved_at": now(),
                 "source_sha256": digest(source.read_bytes()), "scope": "Northbridge Services teaching environment"}
                for eid, (locator, quote) in passages.items()]

    def fact(value, refs, **extra):
        return {"value": value, "evidence_ids": refs, **extra}

    baseline = {"snapshot_id": "northbridge-docx-v1", "scenario": "baseline", "asset_id": "N02",
                "threat_id": CVE, "source_mode": "simulated", "cohort_count": 2,
                "assessment_scope": "N02 cohort; individual gateway versions and configurations are not supplied",
                "source_document": source.name, "source_document_sha256": digest(source.read_bytes()),
                "created_at": now(), "facts": {
                    "product": fact("FortiOS", ["ENV-ASSET"]),
                    "firmware": fact(None, ["ENV-UNKNOWN"]),
                    "ssl_vpn_enabled": fact(None, ["ENV-ASSET", "ENV-NETWORK"]),
                    "attack_path": fact(None, ["ENV-NETWORK", "S02"]),
                    "internet_reachable": fact(None, ["ENV-NETWORK"]),
                    "impact": fact("High", ["ENV-ASSET", "ENV-ORGANIZATION"],
                                   interpretation=True, reason="Production remote-access gateway compromise or interruption could materially disrupt work; simultaneous dependency of all remote staff is not asserted.")},
                "evidence": evidence, "assumptions": ["High impact is a policy interpretation of the production remote-access role, pending analyst review."],
                "limitations": ["DOCX-derived subset; companion JSON/CSV/lookup script were not supplied.",
                                "The original DOCX documents public VPN TCP/443 but does not identify SSL-VPN termination or enabled status; fixture values are explicit simulated overrides.",
                                "No per-gateway state, configuration date, exact internal flows, or VPN-specific RTO is supplied.",
                                "No telemetry events establish actual exploitation or compromise."], "overrides": []}
    write_json(ROOT / "data/environment/baseline.json", baseline)

    overrides = {
        "positive": {"firmware": "7.2.6", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True},
        "patched": {"firmware": "7.2.7", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True},
        "internal": {"firmware": "7.2.6", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": False},
        "medium": {"firmware": "7.2.6", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True, "impact": "Medium"},
        "low": {"firmware": "7.2.6", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True, "impact": "Low"},
        "missing": {"firmware": None, "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True},
        "conflicting": {"firmware": "conflicting", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": True},
        "unknown-exposure": {"firmware": "7.2.6", "ssl_vpn_enabled": True, "attack_path": True, "internet_reachable": None},
        "disabled": {"firmware": "7.2.6", "ssl_vpn_enabled": False, "attack_path": None, "internet_reachable": None}
    }
    for name, changes in overrides.items():
        variant = deepcopy(baseline)
        variant.update(snapshot_id="northbridge-" + name + "-v1", scenario=name,
                       assessment_scope="One explicitly simulated N02 test instance; does not assert the state of both cohort members")
        for field, value in changes.items():
            eid = "SIM-" + name.upper() + "-" + field.upper()
            quote = f"Test override: {field} = {json.dumps(value)}."
            if field == "attack_path" and value is True:
                quote += " An unauthenticated threat source can reach the affected SSL-VPN service within the fixture's declared scope."
            if field == "internet_reachable" and value is False:
                quote += " Internet ingress to SSL-VPN is denied; an internal threat source retains a permitted route."
            if field == "impact" and value == "Medium":
                quote += " Noncritical test-team service; limited interruption; documented separation from production and sensitive data."
            if field == "impact" and value == "Low":
                quote += " Disposable isolated test service; synthetic data, no sensitive credentials or production dependencies, negligible operational consequences. Isolation limits consequences but a lab threat source can reach SSL-VPN."
            record = {"evidence_id": eid, "publisher": "Group controlled scenario variant", "source": f"data/environment/{name}.json",
                      "locator": f"/facts/{field}", "quote": quote, "source_mode": "simulated", "source_date": None,
                      "retrieved_at": now(), "scope": variant["assessment_scope"]}
            if value == "conflicting":
                record["conflicting_records"] = [{"value": "7.2.6", "scope": "same simulated instance and snapshot time"},
                                                 {"value": "7.2.7", "scope": "same simulated instance and snapshot time"}]
            variant["evidence"].append(record)
            variant["overrides"].append({"field": field, "before": variant["facts"][field]["value"], "after": value, "evidence_id": eid})
            variant["facts"][field] = fact(value, [eid])
        if name in {"medium", "low"}:
            variant["assumptions"] = []
        write_json(ROOT / f"data/environment/{name}.json", variant)
    print("Derived baseline and nine labeled variants; original DOCX unchanged.")


if __name__ == "__main__":
    prepare()
