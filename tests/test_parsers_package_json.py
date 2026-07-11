"""Tests for the package.json script parser."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi.parsers import package_json


def _parse(scripts: dict) -> list:
    return package_json.parse(Path("package.json"), json.dumps({"scripts": scripts}))


def test_should_parse_only_package_json() -> None:
    assert package_json.should_parse(Path("package.json")) is True
    assert package_json.should_parse(Path("frontend/package.json")) is True
    assert package_json.should_parse(Path("package-lock.json")) is False


def test_invalid_json_returns_no_signals() -> None:
    assert package_json.parse(Path("package.json"), "{not json") == []


def test_health_check_curl_not_flagged_as_secret() -> None:
    signals = _parse({"check": "curl localhost:3000/health"})
    assert not any(s["rule_id"] == "nhi_hardcoded_secret" for s in signals)


def test_env_reference_assignment_not_flagged() -> None:
    signals = _parse({"publish": "publish-tool --api_key=$API_KEY"})
    assert not any(s["rule_id"] == "nhi_hardcoded_secret" for s in signals)


def test_literal_secret_assignment_flagged_and_masked() -> None:
    signals = _parse({"publish": "publish-tool --token=GNOC_FAKE_SECRET_DO_NOT_USE_NPM_112233"})
    secrets = [s for s in signals if s["rule_id"] == "nhi_hardcoded_secret"]
    assert len(secrets) == 1
    assert secrets[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_NPM_112233"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in secrets[0]["evidence"][0]


def test_curl_pipe_sh_flagged_as_remote_execution() -> None:
    signals = _parse({"setup": "curl -sSL https://get.example.com/install.sh | sh"})
    assert any(s["rule_id"] == "nhi_npm_script_remote_execution" for s in signals)
    assert not any(s["rule_id"] == "nhi_hardcoded_secret" for s in signals)


def test_plain_deploy_script_downgraded_to_low_confidence() -> None:
    signals = _parse({"deploy": "gh-pages -d dist"})
    deploys = [s for s in signals if s["rule_id"] == "nhi_environment_isolation_failure"]
    assert len(deploys) == 1
    assert deploys[0]["confidence"] == "low"
    assert deploys[0]["production_access"] is False


def test_deploy_script_with_inline_secret_keeps_production_access() -> None:
    signals = _parse({"deploy": "deploy-tool --token=GNOC_FAKE_SECRET_DO_NOT_USE_DEPLOY_998877"})
    deploys = [s for s in signals if s["rule_id"] == "nhi_environment_isolation_failure"]
    assert len(deploys) == 1
    assert deploys[0]["production_access"] is True
    assert any(s["rule_id"] == "nhi_hardcoded_secret" for s in signals)
