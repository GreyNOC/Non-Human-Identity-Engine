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
