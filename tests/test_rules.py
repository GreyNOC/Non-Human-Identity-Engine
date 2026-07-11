import re
from pathlib import Path

from greynoc_nhi.engine import normalize_signal
from greynoc_nhi.owasp_mapping import map_rule_to_owasp
from greynoc_nhi.rules import RULE_CATALOG, make_finding, run_rules

PARSERS_DIR = Path(__file__).resolve().parents[1] / "greynoc_nhi" / "parsers"
RULE_ID_LITERAL_RE = re.compile(r"rule_id=\s*[\"']([^\"']+)[\"']")

FAKE_SECRET = "GNOC_FAKE_SECRET_DO_NOT_USE_123456"


def test_rules_generate_secret_leakage_finding():
    identity = normalize_signal({"rule_id": "nhi_secret_leakage", "file_path": "x", "line_number": 1, "name": "API_KEY", "identity_type": "API key", "source": "test", "evidence": ["API_KEY=ABCD...WXYZ"], "secret_value": FAKE_SECRET})
    findings = run_rules([identity])
    assert any(f.rule_id == "nhi_secret_leakage" for f in findings)


def test_every_parser_rule_id_literal_is_registered_in_catalog():
    """Regression guard: parsers must never emit rule ids missing from RULE_CATALOG.

    Unregistered rule ids silently drop structural findings and demote secret
    findings to the generic nhi_secret_leakage rule.
    """
    found: dict[str, set[str]] = {}
    for parser_file in sorted(PARSERS_DIR.glob("*.py")):
        for match in RULE_ID_LITERAL_RE.finditer(parser_file.read_text(encoding="utf-8")):
            found.setdefault(match.group(1), set()).add(parser_file.name)
    assert len(found) >= 50, "expected to discover parser rule_id literals; glob or regex is broken"
    orphans = {rule_id: sorted(files) for rule_id, files in found.items() if rule_id not in RULE_CATALOG}
    assert not orphans, f"parser rule_ids missing from RULE_CATALOG: {orphans}"


def test_newly_registered_rules_have_owasp_mappings():
    newly_registered = [
        "nhi_npm_registry_token_in_npmrc",
        "nhi_pypi_token_in_pypirc",
        "nhi_cargo_registry_token",
        "nhi_gradle_repository_credential",
        "nhi_netrc_credential",
        "nhi_gitlab_ci_plaintext_variable",
        "nhi_gitlab_ci_job_token_exposure",
        "nhi_gitlab_ci_oidc_id_token",
        "nhi_gitlab_ci_vault_secrets",
        "nhi_gitlab_ci_unprotected_environment",
        "nhi_gitlab_ci_deployment_without_protected_check",
        "nhi_renovate_host_rules_plaintext_token",
        "nhi_renovate_automerge_enabled",
        "nhi_renovate_vulnerability_alerts_disabled",
        "nhi_renovate_extends_github_preset",
        "nhi_renovate_bot_identity",
        "nhi_dependabot_bot_identity",
        "nhi_dependabot_targets_protected_branch",
        "nhi_helm_values_plaintext_secret",
        "nhi_helm_values_image_pull_secret_inline",
        "nhi_pulumi_config_plaintext_secret",
        "nhi_aws_cdk_context_secret",
        "nhi_bicep_param_missing_secure_decorator",
        "nhi_bicep_param_default_plaintext_secret",
        "nhi_terraform_state_plaintext_secret",
        "nhi_history_secret_still_current",
    ]
    for rule_id in newly_registered:
        assert rule_id in RULE_CATALOG, f"{rule_id} missing from RULE_CATALOG"
        assert map_rule_to_owasp(rule_id), f"{rule_id} has no OWASP NHI mapping"


def test_structural_parser_rule_yields_specific_finding():
    """A non-secret structural signal must produce its own primary finding."""
    identity = normalize_signal(
        {
            "rule_id": "nhi_gitlab_ci_deployment_without_protected_check",
            "file_path": ".gitlab-ci.yml",
            "line_number": 12,
            "name": "GitLab deployment without protected-branch gate",
            "identity_type": "deployment_identity",
            "source": "gitlab ci",
            "evidence": ["deployment job lacks $CI_COMMIT_REF_PROTECTED rule"],
            "production_access": True,
            "tags": ["ci_cd", "gitlab", "missing_gate"],
        }
    )
    findings = run_rules([identity])
    assert any(f.rule_id == "nhi_gitlab_ci_deployment_without_protected_check" for f in findings)


def test_tfstate_secret_yields_specific_high_severity_finding():
    identity = normalize_signal(
        {
            "rule_id": "nhi_terraform_state_plaintext_secret",
            "file_path": "terraform.tfstate",
            "line_number": 8,
            "name": "Terraform state secret: password",
            "identity_type": "cloud_workload_identity",
            "source": "terraform state",
            "evidence": [f"resources.instances.attributes.password={FAKE_SECRET}"],
            "secret_value": FAKE_SECRET,
            "production_access": True,
            "tags": ["terraform", "tfstate", "plaintext_secret"],
            "confidence": "high",
        }
    )
    findings = run_rules([identity])
    tfstate = [f for f in findings if f.rule_id == "nhi_terraform_state_plaintext_secret"]
    assert tfstate, "tfstate secret must not collapse into generic nhi_secret_leakage"
    assert tfstate[0].risk_score == 90
    assert tfstate[0].severity == "critical"
    assert not any(f.rule_id == "nhi_secret_leakage" for f in findings)


def test_history_secret_still_current_rule_is_registered():
    identity = normalize_signal(
        {
            "rule_id": "nhi_history_secret_still_current",
            "file_path": ".env",
            "line_number": 3,
            "name": "history secret still current",
            "identity_type": "api_key",
            "source": "advanced correlation",
            "evidence": ["Secret committed at abc1234 is still present in .env"],
            "tags": ["advanced_correlation", "git_history"],
        }
    )
    findings = run_rules([identity])
    matches = [f for f in findings if f.rule_id == "nhi_history_secret_still_current"]
    assert matches
    assert matches[0].risk_score == 85
    assert "NHI7:2025" in matches[0].owasp_nhi_refs


def test_low_confidence_finding_is_damped_one_band():
    base = {
        "rule_id": "nhi_database_url_with_credentials",
        "file_path": "config.ini",
        "line_number": 2,
        "name": "DATABASE_URL",
        "identity_type": "database credential",
        "source": "test",
        "evidence": ["DATABASE_URL=postgres://user:****@host/db"],
        "secret_value": FAKE_SECRET,
    }
    low = normalize_signal({**base, "confidence": "low"})
    high = normalize_signal({**base, "confidence": "high"})
    low_finding = make_finding("nhi_database_url_with_credentials", low)
    high_finding = make_finding("nhi_database_url_with_credentials", high)
    assert high_finding.risk_score == 80
    assert low_finding.risk_score == 55
    assert high_finding.severity == "high"
    assert low_finding.severity == "medium"


def test_low_confidence_damping_has_score_floor():
    identity = normalize_signal(
        {
            "rule_id": "nhi_missing_owner",
            "file_path": "x",
            "line_number": 1,
            "name": "identity",
            "identity_type": "api_key",
            "source": "test",
            "evidence": ["no owner"],
            "confidence": "low",
        }
    )
    finding = make_finding("nhi_missing_owner", identity)
    assert finding.risk_score == 20


def test_unowned_credential_suppresses_redundant_rotation_and_owner_findings():
    identity = normalize_signal(
        {
            "rule_id": "nhi_npm_registry_token_in_npmrc",
            "file_path": ".npmrc",
            "line_number": 1,
            "name": "//registry.npmjs.org/:_authToken",
            "identity_type": "api_key",
            "source": ".npmrc",
            "evidence": ["//registry.npmjs.org/:_authToken=****"],
            "secret_value": FAKE_SECRET,
            "external_access": True,
            "tags": ["npm", "package_registry"],
        }
    )
    findings = run_rules([identity])
    rule_ids = {f.rule_id for f in findings}
    assert "nhi_long_lived_unowned_credential" in rule_ids
    assert "nhi_long_lived_secret" not in rule_ids
    assert "nhi_no_rotation_policy" not in rule_ids
    assert "nhi_missing_owner" not in rule_ids
    # Non-overlapping governance evidence still fires.
    assert "nhi_missing_logging_evidence" in rule_ids


def test_owned_credential_still_gets_rotation_findings():
    identity = normalize_signal(
        {
            "rule_id": "nhi_secret_leakage",
            "file_path": ".env",
            "line_number": 1,
            "name": "API_KEY",
            "identity_type": "api_key",
            "source": "test",
            "evidence": ["API_KEY=****"],
            "secret_value": FAKE_SECRET,
            "owner": "platform-team",
        }
    )
    findings = run_rules([identity])
    rule_ids = {f.rule_id for f in findings}
    assert "nhi_long_lived_unowned_credential" not in rule_ids
    assert "nhi_long_lived_secret" in rule_ids
    assert "nhi_no_rotation_policy" in rule_ids


def _secret_signal(rule_id: str, file_path: str, line_number: int) -> dict:
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "line_number": line_number,
        "name": f"{rule_id}@{file_path}",
        "identity_type": "api_key",
        "source": "test",
        "evidence": ["TOKEN=****"],
        "secret_value": FAKE_SECRET,
    }


def test_reuse_not_fired_for_same_line_matched_by_multiple_parsers():
    """Two parsers matching the same secret on the same line is not reuse."""
    first = normalize_signal(_secret_signal("nhi_secret_leakage", ".npmrc", 3))
    second = normalize_signal(_secret_signal("nhi_package_registry_token_detected", ".npmrc", 3))
    assert first.secret_fingerprint == second.secret_fingerprint
    findings = run_rules([first, second])
    assert not any(f.rule_id == "nhi_nhi_reuse_suspected" for f in findings)


def test_reuse_fires_for_same_secret_in_distinct_locations():
    first = normalize_signal(_secret_signal("nhi_secret_leakage", ".env", 1))
    second = normalize_signal(_secret_signal("nhi_secret_leakage", "docker-compose.yml", 14))
    assert first.secret_fingerprint == second.secret_fingerprint
    findings = run_rules([first, second])
    reuse = [f for f in findings if f.rule_id == "nhi_nhi_reuse_suspected"]
    assert len(reuse) == 2
    assert {f.file_path for f in reuse} == {".env", "docker-compose.yml"}
