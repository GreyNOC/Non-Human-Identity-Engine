"""Baseline read/write and new-finding evaluation."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from greynoc_nhi.models import Finding, ScanResult
from greynoc_nhi.utils import assert_no_raw_secret_markers, chmod_private_file, stable_id

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def finding_baseline_key(finding: Finding) -> str:
    evidence = " ".join(str(item).strip().lower() for item in finding.evidence if str(item).strip())
    if evidence:
        return stable_id(
            "base",
            finding.rule_id,
            finding.file_path or "",
            evidence,
        )
    return stable_id(
        "base",
        finding.rule_id,
        finding.file_path or "",
        finding.identity_name or "",
        finding.title,
    )


def baseline_entries(scan: ScanResult) -> list[dict[str, object]]:
    entries = []
    for finding in scan.findings:
        key = finding.baseline_key or finding_baseline_key(finding)
        entries.append(
            {
                "key": key,
                "rule_id": finding.rule_id,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "identity_name": finding.identity_name,
                "title": finding.title,
                "severity": finding.severity,
                "accepted_by": None,
                "accepted_until": None,
                "reason": None,
                "review_required": True,
            }
        )
    return entries


def write_baseline(scan: ScanResult, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps({"version": 2, "findings": baseline_entries(scan)}, indent=2)
    assert_no_raw_secret_markers(content)
    out.write_text(content, encoding="utf-8")
    chmod_private_file(out)
    return out


def _baseline_item_active(item: dict) -> bool:
    accepted_until = item.get("accepted_until")
    if accepted_until:
        try:
            if date.fromisoformat(str(accepted_until)) < date.today():
                return False
        except ValueError:
            return False
    if item.get("review_required") is True and accepted_until:
        return False
    return True


def read_baseline(path: str | Path | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return {str(item.get("key")) for item in findings if isinstance(item, dict) and item.get("key") and _baseline_item_active(item)}


def apply_baseline(scan: ScanResult, path: str | Path | None) -> ScanResult:
    keys = read_baseline(path)
    known = 0
    for finding in scan.findings:
        key = finding_baseline_key(finding)
        finding.baseline_key = key
        if key in keys:
            finding.baseline_status = "known"
            known += 1
        else:
            finding.baseline_status = "new"
    scan.stats["baseline_known_findings"] = known
    scan.stats["baseline_new_findings"] = len(scan.findings) - known
    return scan


def has_new_findings_at_or_above(scan: ScanResult, severity: str | None) -> bool:
    if not severity:
        return False
    threshold = SEVERITY_ORDER[severity.lower()]
    return any(finding.baseline_status != "known" and SEVERITY_ORDER[finding.severity] >= threshold for finding in scan.findings)
