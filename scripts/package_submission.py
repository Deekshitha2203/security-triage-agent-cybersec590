# this builds the submission zip from a fixed list of files and checks no secret gets in
from pathlib import Path 
import json
import re
import os
from zipfile import ZipFile, ZIP_DEFLATED

from triage.common import ROOT, SafeError, SECRET_ENV, digest, now, write_json


def selected_files():   # picks which files go into the zip, and only allowed folders and file types get in. Excludes .env or the key pdf
    files = [ROOT / n for n in ("README.md", "requirements.txt", ".env.example", ".gitignore",
                               "Assignment 3_ Build a Security Triage Agent.pdf", "Windows_Enterprise_Environment.docx")]
    for folder in ("triage", "scripts", "tests", "config", "docs", "data", "artifacts"):
        for p in sorted((ROOT / folder).rglob("*")):
            if p.is_file() and not p.is_symlink() and p.suffix in {".py", ".json", ".md", ".html"} and "__pycache__" not in p.parts and not any(part.startswith("private-") for part in p.parts):
                files.append(p)
    return sorted(set(p for p in files if p.is_file()))


def scan(files): # looks through every file for our real api key or anything that looks like a key
    findings = []
    values = [os.environ[k].encode() for k in SECRET_ENV if os.environ.get(k)]
    for p in files:
        raw = p.read_bytes()
        name = str(p.relative_to(ROOT))
        if any(v in raw for v in values):
            findings.append({"path": name, "reason": "configured_credential_value_detected"})
        if p.suffix not in {".pdf", ".docx"}:
            text = raw.decode("utf-8", errors="replace")
            if re.search(r"\bsk-[A-Za-z0-9_-]{16,}\b", text):
                findings.append({"path": name, "reason": "credential_pattern_detected"})
            if re.search(r"(?i)Bearer\s+(?!\[REDACTED\]|YOUR_|<)[A-Za-z0-9._~+/=-]{16,}", text):
                findings.append({"path": name, "reason": "bearer_credential_pattern_detected"})
    return findings


def package_submission(output):  # makes the zip and an audit file listing every file with its hash, stops if a key is found
    files = selected_files()
    findings = scan(files)
    audit = {"created_at": now(), "allowlist_file_count": len(files), "secret_findings": findings,
             "credential_pdf_excluded": not any("Recorded Future" in p.name for p in files),
             "local_secret_configuration_excluded": not any(p.name == ".env" for p in files),
             "note": "Scans known configured credential values and common patterns; no credential values are logged.",
             "files": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in files}}
    if findings:
        raise SafeError("submission_secret_scan_failed; remove identified credentials before packaging")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output.parent / "package_audit.json", audit)
    with ZipFile(output, "w", ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, "security-triage-agent/" + str(p.relative_to(ROOT)))
        z.writestr("security-triage-agent/package_audit.json", json.dumps(audit, indent=2) + "\n")
    print(f"Sanitized ZIP saved: {output}; {len(files)} allowlisted files, no detected credentials.")


if __name__ == "__main__":
    package_submission(ROOT / "dist/security-triage-agent.zip")
