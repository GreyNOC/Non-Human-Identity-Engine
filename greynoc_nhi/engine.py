"""Scan orchestration engine."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.advanced import synthesize_advanced_signals
from greynoc_nhi.masking import fingerprint_secret, mask_secret
from greynoc_nhi.models import NonHumanIdentity, ScanResult
from greynoc_nhi.rules import run_rules
from greynoc_nhi.scanner import Scanner
from greynoc_nhi.scoring import calculate_overall_score, severity_label
from greynoc_nhi.storage import Storage
from greynoc_nhi.utils import stable_id, utc_now


def normalize_signal(signal: dict) -> NonHumanIdentity:
    """Convert parser signal dictionaries into safe NHI model objects."""
    secret_value = signal.get("secret_value")
    tags = sorted(set([signal.get("rule_id"), *signal.get("tags", [])]))
    secret_fingerprint = fingerprint_secret(secret_value) if secret_value else None
    masked_secret = mask_secret(secret_value) if secret_value else None
    return NonHumanIdentity(
        id=stable_id("nhi", signal.get("file_path"), signal.get("line_number"), signal.get("name"), signal.get("rule_id"), secret_fingerprint or ""),
        name=signal.get("name") or "Unknown NHI",
        identity_type=signal.get("identity_type") or "non-human identity",
        source=signal.get("source") or "scanner",
        file_path=signal.get("file_path"),
        line_number=signal.get("line_number"),
        owner=signal.get("owner"),
        environment=signal.get("environment"),
        provider=signal.get("provider"),
        secret_age_days=signal.get("secret_age_days"),
        permissions=signal.get("permissions", []),
        scopes=signal.get("scopes", []),
        tools=signal.get("tools", []),
        has_secret=bool(secret_value or "plaintext_secret" in tags),
        secret_fingerprint=secret_fingerprint,
        masked_secret=masked_secret,
        admin_access=bool(signal.get("admin_access")),
        production_access=bool(signal.get("production_access")),
        external_access=bool(signal.get("external_access")),
        data_access_level=signal.get("data_access_level") or "unknown",
        logging_enabled=signal.get("logging_enabled"),
        rotation_status=signal.get("rotation_status", "missing") if secret_value else signal.get("rotation_status"),
        approval_required=signal.get("approval_required"),
        evidence=signal.get("evidence", []),
        raw_reference=signal.get("raw_reference"),
        tags=tags,
    )


class Engine:
    """Runs scan, rule evaluation, scoring, and optional persistence."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.scanner = Scanner()
        self.storage = Storage(db_path) if db_path else None

    def run_scan(self, project_path: str | Path, persist: bool = True) -> ScanResult:
        started = utc_now()
        raw = self.scanner.scan(project_path)
        identities = [normalize_signal(signal) for signal in raw["signals"]]
        advanced_signals = synthesize_advanced_signals(identities, raw)
        identities.extend(normalize_signal(signal) for signal in advanced_signals)
        findings = run_rules(identities)
        overall = calculate_overall_score(identities, findings)
        completed = utc_now()
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        if findings:
            top = findings[0]
            summary = (
                f"Your project has {critical} critical and {high} high NHI findings. "
                f"The highest-risk issue is: {top.title}. Fix this before production release."
            )
        else:
            summary = "No high-confidence NHI risks were found in the scanned files."
        result = ScanResult(
            scan_id=stable_id("scan", raw["project_path"], started, len(identities), len(findings)),
            project_path=raw["project_path"],
            started_at=started,
            completed_at=completed,
            identities=identities,
            findings=findings,
            overall_score=overall,
            summary=summary,
            stats={
                "scanned_files": raw["scanned_files"],
                "skipped_files": raw["skipped_files"],
                "parser_errors": raw["errors"],
                "advanced_correlations": len(advanced_signals),
                "severity_label": severity_label(overall),
                "critical_findings": critical,
                "high_findings": high,
                "identities_found": len(identities),
                "findings_count": len(findings),
            },
        )
        if persist and self.storage:
            self.storage.save_scan(result)
        return result
