"""Tests for the severity-tiered exit code mode."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from greynoc_nhi.cli import (
    EXIT_CLEAN,
    EXIT_HIGH_CRITICAL,
    EXIT_LOW_MEDIUM,
    EXIT_UNTRUSTED,
    exit_code_for_baseline,
    severity_exit_code,
)
from greynoc_nhi.models import Finding, ScanResult


def _make_scan(findings: list[Finding], trust: str = "clean") -> ScanResult:
    return ScanResult(
        scan_id="x",
        project_path="/tmp",
        started_at="now",
        completed_at="now",
        identities=[],
        findings=findings,
        overall_score=50,
        summary="",
        stats={},
        scan_trust_level=trust,
    )


def _finding(severity: str, baseline_status: str = "new") -> Finding:
    return Finding(
        id=f"f-{severity}",
        rule_id="rule",
        title="example",
        severity=severity,
        risk_score=50,
        category="x",
        identity_id=None,
        identity_name=None,
        source="src",
        file_path="a",
        line_number=1,
        explanation="",
        why_it_matters="",
        evidence=[],
        remediation="",
        priority="p2",
        owasp_nhi_refs=[],
        control_hints=[],
        created_at="now",
        baseline_status=baseline_status,
    )


def test_clean_scan_returns_zero() -> None:
    assert severity_exit_code(_make_scan([])) == EXIT_CLEAN


def test_high_finding_returns_two() -> None:
    assert severity_exit_code(_make_scan([_finding("high")])) == EXIT_HIGH_CRITICAL


def test_critical_finding_returns_two() -> None:
    assert severity_exit_code(_make_scan([_finding("critical")])) == EXIT_HIGH_CRITICAL


def test_medium_finding_returns_one() -> None:
    assert severity_exit_code(_make_scan([_finding("medium")])) == EXIT_LOW_MEDIUM


def test_low_finding_returns_one() -> None:
    assert severity_exit_code(_make_scan([_finding("low")])) == EXIT_LOW_MEDIUM


def test_known_baseline_findings_ignored() -> None:
    assert severity_exit_code(_make_scan([_finding("high", "known")])) == EXIT_CLEAN


def test_untrusted_scan_returns_ten() -> None:
    assert severity_exit_code(_make_scan([], trust="untrusted")) == EXIT_UNTRUSTED


def test_exit_code_dispatch_uses_severity_when_flag_set() -> None:
    args = SimpleNamespace(severity_exit_codes=True, fail_on_new=None)
    scan = _make_scan([_finding("high")])
    assert exit_code_for_baseline(scan, args) == EXIT_HIGH_CRITICAL


def test_exit_code_default_is_legacy_binary(tmp_path: Path) -> None:
    args = SimpleNamespace(severity_exit_codes=False, fail_on_new="high")
    scan = _make_scan([_finding("high")])
    assert exit_code_for_baseline(scan, args) == 1
    args2 = SimpleNamespace(severity_exit_codes=False, fail_on_new=None)
    assert exit_code_for_baseline(scan, args2) == 0


def test_untrusted_scan_fails_closed_under_fail_on_new() -> None:
    """A fatally-errored scan (zero findings) must not exit 0 in gated mode."""
    args = SimpleNamespace(severity_exit_codes=False, fail_on_new="high")
    scan = _make_scan([], trust="untrusted")
    assert exit_code_for_baseline(scan, args) == EXIT_UNTRUSTED


def test_untrusted_scan_without_gating_flags_reports_only() -> None:
    args = SimpleNamespace(severity_exit_codes=False, fail_on_new=None)
    scan = _make_scan([], trust="untrusted")
    assert exit_code_for_baseline(scan, args) == EXIT_CLEAN


def test_untrusted_scan_with_severity_exit_codes_returns_ten() -> None:
    args = SimpleNamespace(severity_exit_codes=True, fail_on_new=None)
    scan = _make_scan([], trust="untrusted")
    assert exit_code_for_baseline(scan, args) == EXIT_UNTRUSTED
