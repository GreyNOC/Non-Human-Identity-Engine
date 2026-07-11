"""Tests for the GitLab CI parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import gitlab_ci


def test_should_parse_gitlab_files() -> None:
    assert gitlab_ci.should_parse(Path(".gitlab-ci.yml")) is True
    assert gitlab_ci.should_parse(Path(".gitlab-ci.yaml")) is True
    assert gitlab_ci.should_parse(Path("workflow.yml")) is False


def test_detects_plaintext_secret_in_variables() -> None:
    text = """
variables:
  DEPLOY_TOKEN: GNOC_FAKE_SECRET_DO_NOT_USE_GITLAB_111122
  HARMLESS: hello

build:
  script:
    - echo done
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_gitlab_ci_plaintext_variable" in rules


def test_skips_variable_referencing_other_var() -> None:
    text = """
variables:
  DEPLOY_TOKEN: $REAL_SECRET
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_gitlab_ci_plaintext_variable" for s in signals)


def test_detects_oidc_id_token() -> None:
    text = """
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_oidc_id_token" for s in signals)


def test_detects_vault_secrets_binding() -> None:
    text = """
deploy:
  secrets:
    DATABASE_URL:
      vault: production/db/url@ops
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_vault_secrets" for s in signals)


def test_detects_unprotected_environment() -> None:
    text = """
deploy:
  environment:
    name: production
    protected: false
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_unprotected_environment" for s in signals)


def test_detects_job_token_exposure_to_external_image() -> None:
    text = """
deploy:
  image: registry.example.com/external:latest
  trigger:
    project: parent/group
    forward:
      yaml_variables: false
      pipeline_variables: false
    variables:
      EXAMPLE: $CI_JOB_TOKEN
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_job_token_exposure" for s in signals)


def test_detects_ci_debug_trace_enabled() -> None:
    text = """
variables:
  CI_DEBUG_TRACE: "true"
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    debug = [s for s in signals if s["rule_id"] == "nhi_gitlab_ci_debug_trace_enabled"]
    assert len(debug) == 1
    assert debug[0]["confidence"] == "high"
    assert debug[0]["line_number"] == 3


def test_detects_ci_debug_services_enabled() -> None:
    text = """
variables:
  CI_DEBUG_SERVICES: true
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_debug_trace_enabled" for s in signals)


def test_debug_trace_false_not_flagged() -> None:
    text = """
variables:
  CI_DEBUG_TRACE: "false"
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_gitlab_ci_debug_trace_enabled" for s in signals)


def test_detects_dind_service_in_services_block() -> None:
    text = """
build:
  services:
    - docker:24-dind
  script:
    - docker build .
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    dind = [s for s in signals if s["rule_id"] == "nhi_gitlab_ci_dind_privileged"]
    assert len(dind) == 1
    assert dind[0]["line_number"] == 4


def test_detects_dind_image() -> None:
    text = """
build:
  image: docker:24-dind
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert any(s["rule_id"] == "nhi_gitlab_ci_dind_privileged" for s in signals)


def test_dind_in_comment_not_flagged() -> None:
    text = """
build:
  image: alpine  # not docker:dind anymore
  script:
    - echo done
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_gitlab_ci_dind_privileged" for s in signals)


def test_single_pass_refactor_preserves_rule_set_and_lines() -> None:
    text = """
variables:
  API_TOKEN: GNOC_FAKE_SECRET_DO_NOT_USE_GITLAB_222333

deploy:
  environment:
    name: production
    protected: false
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'
  trigger:
    project: group/other
    variables:
      UPSTREAM: $CI_JOB_TOKEN
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  secrets:
    DATABASE_URL:
      vault: production/db/url@ops
"""
    signals = gitlab_ci.parse(Path(".gitlab-ci.yml"), text)
    by_rule = {s["rule_id"]: s for s in signals}
    assert by_rule["nhi_gitlab_ci_plaintext_variable"]["line_number"] == 3
    assert by_rule["nhi_gitlab_ci_unprotected_environment"]["line_number"] == 8
    assert by_rule["nhi_gitlab_ci_job_token_exposure"]["line_number"] == 14
    assert by_rule["nhi_gitlab_ci_oidc_id_token"]["line_number"] == 15
    assert by_rule["nhi_gitlab_ci_vault_secrets"]["line_number"] == 18
    assert "nhi_gitlab_ci_deployment_without_protected_check" in by_rule
