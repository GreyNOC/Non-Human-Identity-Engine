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
    assert iac_extra.should_parse(Path("Jenkinsfile")) is True
    assert iac_extra.should_parse(Path("Jenkinsfile.prod")) is True
    assert iac_extra.should_parse(Path("repo/.circleci/config.yml")) is True
    assert iac_extra.should_parse(Path("azure-pipelines.yml")) is True
    assert iac_extra.should_parse(Path("bitbucket-pipelines.yml")) is True


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


def test_bicep_inline_secure_decorator_is_clean() -> None:
    text = """
@secure() param sqlAdminPassword string
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    assert not any(s["rule_id"] == "nhi_bicep_param_missing_secure_decorator" for s in signals)


def test_bicep_stacked_decorators_are_clean() -> None:
    text = """
@secure()
@description('database admin password')
param dbAdminPassword string
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    assert not any(s["rule_id"] == "nhi_bicep_param_missing_secure_decorator" for s in signals)


def test_bicep_secure_decorator_of_previous_param_does_not_leak() -> None:
    text = """
@secure()
param first string
param apiToken string
"""
    signals = iac_extra.parse(Path("main.bicep"), text)
    flagged = [s["name"] for s in signals if s["rule_id"] == "nhi_bicep_param_missing_secure_decorator"]
    assert flagged == ["apiToken"]


def test_cdk_line_number_resolved_via_offsets() -> None:
    data = {
        "context": {
            "stage": "dev",
            "deployToken": "GNOC_FAKE_SECRET_DO_NOT_USE_CDKLINE_112358",
        }
    }
    text = json.dumps(data, indent=2)
    signals = iac_extra.parse(Path("cdk.json"), text)
    assert signals
    expected_line = next(
        i for i, line in enumerate(text.splitlines(), 1) if "deployToken" in line
    )
    assert signals[0]["line_number"] == expected_line


def test_jenkins_environment_literal_secret_detected() -> None:
    text = """
pipeline {
  agent any
  environment {
    DEPLOY_TOKEN = 'GNOC_FAKE_SECRET_DO_NOT_USE_JENKINS_998877'
    REGION = 'us-east-1'
  }
}
"""
    signals = iac_extra.parse(Path("Jenkinsfile"), text)
    creds = [s for s in signals if s["rule_id"] == "nhi_hardcoded_secret"]
    assert len(creds) == 1
    assert creds[0]["name"] == "DEPLOY_TOKEN"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in creds[0]["evidence"][0]


def test_jenkins_credentials_binding_inventory() -> None:
    text = """
pipeline {
  environment {
    AWS_CREDS = credentials('aws-deploy')
  }
  stages {
    stage('deploy') {
      steps {
        withCredentials([string(credentialsId: 'token-id', variable: 'TOKEN')]) {
          sh './deploy.sh'
        }
      }
    }
  }
}
"""
    signals = iac_extra.parse(Path("Jenkinsfile"), text)
    bindings = [s for s in signals if s["rule_id"] == "nhi_jenkins_credentials_binding"]
    assert len(bindings) == 2


def test_jenkins_curl_pipe_sh_detected() -> None:
    text = """
pipeline {
  stages {
    stage('setup') {
      steps {
        sh 'curl -sSL https://get.example.com/install.sh | bash'
      }
    }
  }
}
"""
    signals = iac_extra.parse(Path("Jenkinsfile"), text)
    assert any(s["rule_id"] == "nhi_ci_remote_script_execution" for s in signals)


def test_jenkins_commented_curl_not_flagged() -> None:
    text = """
pipeline {
  stages {
    // sh 'curl https://get.example.com | sh'
  }
}
"""
    signals = iac_extra.parse(Path("Jenkinsfile"), text)
    assert not any(s["rule_id"] == "nhi_ci_remote_script_execution" for s in signals)


def test_circleci_unpinned_orb_detected() -> None:
    text = """
version: 2.1
orbs:
  aws-cli: circleci/aws-cli@volatile
  slack: circleci/slack@4.12.5
"""
    signals = iac_extra.parse(Path("repo/.circleci/config.yml"), text)
    unpinned = [s for s in signals if s["rule_id"] == "nhi_ci_unpinned_component"]
    assert len(unpinned) == 1
    assert unpinned[0]["name"] == "circleci/aws-cli"


def test_circleci_remote_docker_and_context_detected() -> None:
    text = """
version: 2.1
jobs:
  build:
    steps:
      - setup_remote_docker
workflows:
  main:
    jobs:
      - build:
          context: org-secrets
"""
    signals = iac_extra.parse(Path("repo/.circleci/config.yml"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_overprivileged_nhi" in rules
    assert "nhi_circleci_context_usage" in rules


def test_circleci_environment_literal_secret_detected() -> None:
    text = """
jobs:
  deploy:
    environment:
      API_TOKEN: GNOC_FAKE_SECRET_DO_NOT_USE_CIRCLE_112233
"""
    signals = iac_extra.parse(Path("repo/.circleci/config.yml"), text)
    creds = [s for s in signals if s["rule_id"] == "nhi_hardcoded_secret"]
    assert len(creds) == 1
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in creds[0]["evidence"][0]


def test_azure_pipelines_access_token_and_persist_credentials() -> None:
    text = """
steps:
  - checkout: self
    persistCredentials: true
  - script: |
      git push origin HEAD
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
"""
    signals = iac_extra.parse(Path("azure-pipelines.yml"), text)
    broad = [s for s in signals if s["rule_id"] == "nhi_ci_cd_broad_permissions"]
    names = {s["name"] for s in broad}
    assert names == {"Azure Pipelines System.AccessToken", "Azure Pipelines persistCredentials"}


def test_bitbucket_unpinned_pipe_detected() -> None:
    text = """
pipelines:
  default:
    - step:
        script:
          - pipe: atlassian/aws-s3-deploy:latest
          - pipe: atlassian/slack-notify:2.1.0
"""
    signals = iac_extra.parse(Path("bitbucket-pipelines.yml"), text)
    unpinned = [s for s in signals if s["rule_id"] == "nhi_ci_unpinned_component"]
    assert len(unpinned) == 1
    assert unpinned[0]["name"] == "atlassian/aws-s3-deploy:latest"
