"""SARIF 2.1.0 export for GreyNOC findings."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi.models import Finding, ScanResult

SARIF_VERSION = "2.1.0"


def _level(finding: Finding) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(finding.severity, "warning")


def sarif_dict(scan: ScanResult) -> dict:
    rules_by_id: dict[str, Finding] = {}
    for finding in scan.findings:
        rules_by_id.setdefault(finding.rule_id, finding)
    rules = []
    for rule_id, finding in sorted(rules_by_id.items()):
        rules.append(
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.explanation},
                "help": {
                    "text": f"{finding.remediation}\n\nOWASP NHI: {', '.join(finding.owasp_nhi_refs) or 'Unmapped'}"
                },
                "properties": {
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "owasp_nhi_refs": finding.owasp_nhi_refs,
                    "control_hints": finding.control_hints,
                },
            }
        )
    results = []
    for finding in scan.findings:
        region = {"startLine": finding.line_number or 1}
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _level(finding),
                "message": {"text": f"{finding.title}: {finding.why_it_matters} Remediation: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path or scan.project_path},
                            "region": region,
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "priority": finding.priority,
                    "baseline_status": finding.baseline_status,
                    "related_identities": finding.related_identities,
                    "owasp_nhi_refs": finding.owasp_nhi_refs,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GreyNOC Non-Human Identity Risk Engine",
                        "informationUri": "https://github.com/GreyNOC/Non-Human-Identity-Engine",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scan_trust_level": scan.scan_trust_level,
                    "policy_decision": scan.policy_decision,
                    "correlation_id": scan.correlation_id,
                },
            }
        ],
    }


def generate_sarif_report(scan: ScanResult, output_path: str | Path) -> Path:
    out = Path(output_path)
    if out.suffix.lower() != ".sarif" and out.suffix.lower() != ".json":
        out.mkdir(parents=True, exist_ok=True)
        out = out / f"{scan.scan_id}.sarif"
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif_dict(scan), indent=2), encoding="utf-8")
    return out
