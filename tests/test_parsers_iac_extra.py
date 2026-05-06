"""Tests for the Pulumi / AWS CDK / Azure Bicep parser."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi.parsers import iac_extra


def test_should_parse_relevant_files() -> None:
    assert iac_extra.should_parse(Path("Pulumi.yaml")) is True
    assert iac_extra.should_parse(Path("Pulumi.dev.yaml")) is True
    assert iac_extra.should_parse(Path("cdk.json")) is True
    assert iac_extra.should_parse(Path("cdk.context.json")) is True
    assert iac_extra.should_parse(Path("main.bicep")) is True
    assert iac_extra.should_parse(Path("README.md")) is False


def test_pulumi_detects_plaintext_secret_in_config() -> None:
    text = """
name: my-stack
runtime: python
config:
  myproj:dbPassword: GNOC_FAKE_SECRET_DO_NOT_USE_PULUMIPW_888899
  myproj:region: us-east-1
"""
    signals = iac_extra.parse(Path("Pulumi.dev.yaml"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_pulumi_config_plaintext_secret" in rules


def test_pulumi_skips_template_or_var_references() -> None:
    text = """
config:
  myproj:apiKey: ${SOME_VAR}
  myproj:secretKey: $someShellVar
"""
    signals = iac_extra.parse(Path("Pulumi.yaml"), text)
    assert signals == []


def test_cdk_context_secret_detection() -> None:
    data = {
        "context": {
            "deployToken": "GNOC_FAKE_SECRET_DO_NOT_USE_CDKTOK_998877",
            "stage": "dev",
        }
    }
    signals = iac_extra.parse(Path("cdk.json"), json.dumps(data, indent=2))
    assert any(s["rule_id"] == "nhi_aws_cdk_context_secret" for s in signals)


def test_bicep_param_missing_secure_decorator() -> None:
    text = """
param dbAdminPassword string
param region string = 'eastus'
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    assert any(s["rule_id"] == "nhi_bicep_param_missing_secure_decorator" for s in signals)
    assert all(s["name"] != "region" for s in signals)


def test_bicep_param_with_secure_decorator_is_clean() -> None:
    text = """
@secure()
param dbAdminPassword string
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    assert signals == []


def test_bicep_param_default_plaintext() -> None:
    text = """
param apiKey string = 'GNOC_FAKE_SECRET_DO_NOT_USE_BICEPDEF_445566'
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_bicep_param_default_plaintext_secret" in rules
