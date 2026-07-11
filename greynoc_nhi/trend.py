"""Compare a scan against the previous run to surface new vs resolved findings.

This is the artifact a security manager wants for a weekly status email -
"12 new findings, 4 resolved, 3 unchanged since last scan." The data
already lives in the SQLite scan history; this module just queries it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from greynoc_nhi.baseline import finding_baseline_key
from greynoc_nhi.models import Finding, ScanResult
from greynoc_nhi.storage import Storage


@dataclass
class FindingDelta:
    key: str
    rule_id: str
    title: str
    severity: str
    file_path: str | None
    line_number: int | None


@dataclass
class TrendReport:
    has_prior: bool
    previous_scan_id: str | None
    previous_completed_at: str | None
    new_findings: list[FindingDelta] = field(default_factory=list)
    resolved_findings: list[FindingDelta] = field(default_factory=list)
    unchanged_count: int = 0

    def summary(self) -> str:
        if not self.has_prior:
            return "Trend: no prior scan recorded for this project."
        return (
            f"Trend vs {self.previous_scan_id} ({self.previous_completed_at}): "
            f"{len(self.new_findings)} new, {len(self.resolved_findings)} resolved, "
            f"{self.unchanged_count} unchanged."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_prior": self.has_prior,
            "previous_scan_id": self.previous_scan_id,
            "previous_completed_at": self.previous_completed_at,
            "new_findings": [delta.__dict__ for delta in self.new_findings],
            "resolved_findings": [delta.__dict__ for delta in self.resolved_findings],
            "unchanged_count": self.unchanged_count,
            "summary": self.summary(),
        }


def _delta(finding: Finding, key: str) -> FindingDelta:
    return FindingDelta(
        key=key,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        file_path=finding.file_path,
        line_number=finding.line_number,
    )


def find_previous_scan(storage: Storage, current: ScanResult) -> dict[str, Any] | None:
    """Return the most recent prior scan for the same project_path."""
    return storage.find_previous_scan(current.project_path, current.scan_id)


def compute_trend(storage: Storage | None, current: ScanResult) -> TrendReport:
    if storage is None:
        return TrendReport(has_prior=False, previous_scan_id=None, previous_completed_at=None)
    prior_row = find_previous_scan(storage, current)
    if prior_row is None:
        return TrendReport(has_prior=False, previous_scan_id=None, previous_completed_at=None)
    prior_findings = storage.get_findings(prior_row["scan_id"])
    current_map = {finding_baseline_key(f): f for f in current.findings}
    prior_map = {finding_baseline_key(f): f for f in prior_findings}
    current_keys = set(current_map)
    prior_keys = set(prior_map)
    new_keys = sorted(current_keys - prior_keys)
    resolved_keys = sorted(prior_keys - current_keys)
    unchanged_keys = current_keys & prior_keys
    new_findings = [_delta(current_map[key], key) for key in new_keys]
    resolved_findings = [_delta(prior_map[key], key) for key in resolved_keys]
    return TrendReport(
        has_prior=True,
        previous_scan_id=prior_row["scan_id"],
        previous_completed_at=prior_row["completed_at"],
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_count=len(unchanged_keys),
    )
