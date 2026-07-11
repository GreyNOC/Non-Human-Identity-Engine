import json
from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.engine import Engine
from greynoc_nhi.models import Finding, NonHumanIdentity, ScanResult
from greynoc_nhi.reports import (
    generate_all_reports,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
)
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.utils import utc_now


def _identity(**overrides) -> NonHumanIdentity:
    base = dict(
        id="nhi-1",
        name="API_KEY",
        identity_type="api_key",
        source="env file",
        file_path=".env",
        line_number=1,
        source_file=".env",
        source_line=1,
        masked_secret="[REDACTED:secret len=34 fp=abcd1234]",
        has_secret=True,
        tags=["nhi_plaintext_env_secret", "plaintext_secret"],
    )
    base.update(overrides)
    return NonHumanIdentity(**base)


def _finding(**overrides) -> Finding:
    base = dict(
        id="finding-1",
        rule_id="nhi_plaintext_env_secret",
        title="Plaintext environment secret detected",
        severity="critical",
        risk_score=90,
        category="secret exposure",
        identity_id="nhi-1",
        identity_name="API_KEY",
        source="env file",
        file_path=".env",
        line_number=1,
        explanation="An environment-style value appears to contain a secret.",
        why_it_matters="Plaintext env files get copied around.",
        evidence=["API_KEY=[REDACTED:secret len=34 fp=abcd1234]"],
        remediation="Rotate and move to a secret store.",
        priority="fix now",
        owasp_nhi_refs=["NHI2:2025"],
        control_hints=["rotation"],
        created_at=utc_now(),
    )
    base.update(overrides)
    return Finding(**base)


def _scan(identities, findings, project_path=".") -> ScanResult:
    now = utc_now()
    return ScanResult(
        scan_id="scan_reports_test",
        project_path=str(project_path),
        started_at=now,
        completed_at=now,
        identities=identities,
        findings=findings,
        overall_score=80,
        summary="test scan summary",
        stats={},
    )


def test_report_generation_creates_html():
    temp_dir = mkdtemp(prefix="greynoc_nhi_test_")
    result = Engine(Path(temp_dir) / "db.sqlite3").run_scan(sample_project_path())
    report_dir = Path(mkdtemp(prefix="greynoc_nhi_report_test_"))
    report = generate_html_report(result, report_dir)
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    assert "GreyNOC Non-Human Identity Risk Engine" in text
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in text
    assert 'data-severity=' in text
    assert "<script>" in text
    assert "Search this table..." in text


def test_html_inventory_includes_masked_secret_column(tmp_path: Path):
    scan = _scan([_identity()], [_finding()], project_path=tmp_path)
    report = generate_html_report(scan, tmp_path / "reports")
    text = report.read_text(encoding="utf-8")
    assert "<th>Masked Secret</th>" in text
    assert "[REDACTED:secret len=34 fp=abcd1234]" in text


def test_html_inventory_empty_state_spans_all_columns(tmp_path: Path):
    scan = _scan([], [], project_path=tmp_path)
    report = generate_html_report(scan, tmp_path / "reports")
    text = report.read_text(encoding="utf-8")
    assert '<tr><td colspan="11">No identities found.</td></tr>' in text


def test_markdown_report_contains_inventory_and_findings(tmp_path: Path):
    findings = [
        _finding(id="f-crit", severity="critical", risk_score=90),
        _finding(id="f-high", rule_id="nhi_hardcoded_secret", title="Hardcoded secret detected", severity="high", risk_score=75),
    ]
    scan = _scan([_identity()], findings, project_path=tmp_path)
    report = generate_markdown_report(scan, tmp_path / "reports")
    text = report.read_text(encoding="utf-8")
    assert "- Critical findings: 1" in text
    assert "- High findings: 1" in text
    assert "**API_KEY**" in text
    assert "secret=[REDACTED:secret len=34 fp=abcd1234]" in text
    assert "### CRITICAL Plaintext environment secret detected" in text
    assert "### HIGH Hardcoded secret detected" in text
    assert "`nhi_plaintext_env_secret`" in text


def test_json_report_round_trips(tmp_path: Path):
    scan = _scan([_identity()], [_finding()], project_path=tmp_path)
    report = generate_json_report(scan, tmp_path / "reports")
    data = json.loads(report.read_text(encoding="utf-8"))
    for key in ["scan_id", "project_path", "identities", "findings", "risk_paths", "overall_score", "summary", "stats", "scan_trust_level", "policy_decision", "fatal_errors", "correlation_id"]:
        assert key in data
    assert data["scan_id"] == "scan_reports_test"
    assert len(data["identities"]) == 1
    assert len(data["findings"]) == 1
    assert data["identities"][0]["masked_secret"] == "[REDACTED:secret len=34 fp=abcd1234]"


def test_generate_all_reports_includes_sarif(tmp_path: Path):
    scan = _scan([_identity()], [_finding()], project_path=tmp_path)
    reports = generate_all_reports(scan, tmp_path / "reports")
    assert set(reports) == {"html", "json", "markdown", "sarif"}
    for path in reports.values():
        assert path.exists()
    assert reports["sarif"].suffix == ".sarif"
    sarif_data = json.loads(reports["sarif"].read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
