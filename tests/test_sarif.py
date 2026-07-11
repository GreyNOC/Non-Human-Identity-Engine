"""Content-level tests for the SARIF 2.1.0 exporter."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi import __version__
from greynoc_nhi.baseline import finding_baseline_key
from greynoc_nhi.models import Finding, ScanResult
from greynoc_nhi.sarif import PROJECT_ROOT_URI_BASE_ID, generate_sarif_report, sarif_dict
from greynoc_nhi.utils import utc_now


def _finding(**overrides) -> Finding:
    base = dict(
        id="finding-1",
        rule_id="nhi_hardcoded_secret",
        title="Hardcoded secret detected",
        severity="high",
        risk_score=75,
        category="secret exposure",
        identity_id="nhi-1",
        identity_name="API_KEY",
        source="test",
        file_path=None,
        line_number=3,
        explanation="A token appears hardcoded.",
        why_it_matters="Hardcoded credentials leak easily.",
        evidence=["API_KEY=[REDACTED:secret len=34 fp=abcd1234]"],
        remediation="Rotate the credential.",
        priority="fix now",
        owasp_nhi_refs=["NHI2:2025"],
        control_hints=["rotation"],
        created_at=utc_now(),
    )
    base.update(overrides)
    return Finding(**base)


def _scan(findings: list[Finding], project_path: str | Path = ".") -> ScanResult:
    now = utc_now()
    return ScanResult(
        scan_id="scan_sarif_test",
        project_path=str(project_path),
        started_at=now,
        completed_at=now,
        identities=[],
        findings=findings,
        overall_score=50,
        summary="test scan",
        stats={},
    )


def test_severity_to_level_mapping():
    findings = [
        _finding(id="f-crit", rule_id="rule_a", severity="critical", risk_score=95),
        _finding(id="f-high", rule_id="rule_b", severity="high", risk_score=80),
        _finding(id="f-med", rule_id="rule_c", severity="medium", risk_score=55),
        _finding(id="f-low", rule_id="rule_d", severity="low", risk_score=25),
    ]
    data = sarif_dict(_scan(findings))
    levels = [result["level"] for result in data["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note"]


def test_one_rule_entry_per_rule_id_with_multiple_findings():
    findings = [
        _finding(id="f-1", rule_id="nhi_hardcoded_secret"),
        _finding(id="f-2", rule_id="nhi_hardcoded_secret", line_number=9),
        _finding(id="f-3", rule_id="nhi_plaintext_env_secret"),
    ]
    data = sarif_dict(_scan(findings))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["nhi_hardcoded_secret", "nhi_plaintext_env_secret"]
    assert len(data["runs"][0]["results"]) == 3


def test_relative_forward_slash_uri_with_uribaseid(tmp_path: Path):
    target = tmp_path / "conf" / ".env"
    finding = _finding(file_path=str(target))
    data = sarif_dict(_scan([finding], project_path=tmp_path))
    run = data["runs"][0]
    location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "conf/.env"
    assert "\\" not in location["uri"]
    assert location["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
    root_uri = run["originalUriBaseIds"][PROJECT_ROOT_URI_BASE_ID]["uri"]
    assert root_uri.startswith("file://")
    assert root_uri.endswith("/")


def test_out_of_tree_path_falls_back_without_uribaseid(tmp_path: Path):
    finding = _finding(file_path="/etc/pam.d/sshd")
    data = sarif_dict(_scan([finding], project_path=tmp_path))
    location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "\\" not in location["uri"]
    assert "uriBaseId" not in location


def test_missing_file_path_omits_locations():
    finding = _finding(file_path=None)
    data = sarif_dict(_scan([finding]))
    assert "locations" not in data["runs"][0]["results"][0]


def test_region_start_line_is_at_least_one(tmp_path: Path):
    target = tmp_path / ".env"
    finding = _finding(file_path=str(target), line_number=None)
    data = sarif_dict(_scan([finding], project_path=tmp_path))
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1


def test_security_severity_and_default_configuration():
    findings = [
        _finding(id="f-1", rule_id="rule_a", severity="critical", risk_score=95),
        _finding(id="f-2", rule_id="rule_b", severity="high", risk_score=120),
    ]
    data = sarif_dict(_scan(findings))
    rules = {rule["id"]: rule for rule in data["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["rule_a"]["defaultConfiguration"] == {"level": "error"}
    assert rules["rule_a"]["properties"]["security-severity"] == "9.5"
    assert rules["rule_b"]["properties"]["security-severity"] == "10.0"


def test_partial_fingerprints_are_stable_and_match_baseline_key():
    finding = _finding()
    scan = _scan([finding])
    first = sarif_dict(scan)["runs"][0]["results"][0]["partialFingerprints"]
    second = sarif_dict(scan)["runs"][0]["results"][0]["partialFingerprints"]
    assert first == second
    assert first["greynocBaselineKey/v1"] == finding_baseline_key(finding)
    finding.baseline_key = "explicit-key"
    third = sarif_dict(scan)["runs"][0]["results"][0]["partialFingerprints"]
    assert third["greynocBaselineKey/v1"] == "explicit-key"


def test_tool_driver_carries_engine_version():
    data = sarif_dict(_scan([_finding()]))
    assert data["runs"][0]["tool"]["driver"]["version"] == __version__


def test_generate_sarif_report_output_path_branches(tmp_path: Path):
    scan = _scan([_finding()], project_path=tmp_path)
    explicit = generate_sarif_report(scan, tmp_path / "out.sarif")
    assert explicit == tmp_path / "out.sarif"
    assert explicit.exists()
    as_json = generate_sarif_report(scan, tmp_path / "out.json")
    assert as_json == tmp_path / "out.json"
    directory = generate_sarif_report(scan, tmp_path / "reports")
    assert directory == tmp_path / "reports" / f"{scan.scan_id}.sarif"
    assert directory.exists()
    data = json.loads(explicit.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
