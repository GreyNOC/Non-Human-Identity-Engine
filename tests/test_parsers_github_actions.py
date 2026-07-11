from pathlib import Path

from greynoc_nhi.parsers import github_actions


WORKFLOW = """
name: ci
on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: fake/action@main
      - run: echo ${{ secrets.PROD_TOKEN }}
"""


def test_github_actions_detects_write_all():
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), WORKFLOW)
    assert any(s["rule_id"] == "nhi_github_actions_write_all" for s in signals)


def test_github_actions_detects_unpinned_action():
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), WORKFLOW)
    assert any(s["rule_id"] == "nhi_github_actions_unpinned_action" for s in signals)


def test_should_parse_drops_non_github_ci_families():
    assert github_actions.should_parse(Path("repo/.github/workflows/ci.yml")) is True
    assert github_actions.should_parse(Path("azure-pipelines.yml")) is False
    assert github_actions.should_parse(Path("bitbucket-pipelines.yml")) is False
    assert github_actions.should_parse(Path(".circleci/config.yml")) is False


def test_block_permissions_write_detected_with_line_number():
    text = """
permissions:
  contents: write
  id-token: write
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    perms = {s["evidence"][0]: s["line_number"] for s in signals if s["rule_id"] == "nhi_ci_cd_broad_permissions"}
    assert perms == {"contents: write": 3, "id-token: write": 4}


def test_flow_style_permissions_write_detected():
    text = "permissions: {contents: write, id-token: write}\n"
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    perms = {s["evidence"][0] for s in signals if s["rule_id"] == "nhi_ci_cd_broad_permissions"}
    assert perms == {"contents: write", "id-token: write"}


def test_unpinned_first_party_action_downgraded_to_low_confidence():
    text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    unpinned = [s for s in signals if s["rule_id"] == "nhi_github_actions_unpinned_action"]
    assert len(unpinned) == 1
    assert unpinned[0]["confidence"] == "low"
    assert "first_party" in unpinned[0]["tags"]


def test_digest_pinned_docker_action_not_flagged():
    text = """
jobs:
  build:
    steps:
      - uses: docker://ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_github_actions_unpinned_action" for s in signals)


def test_commented_uses_line_not_flagged():
    text = """
jobs:
  build:
    steps:
      # uses: foo/bar@main
      - run: echo ok
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_github_actions_unpinned_action" for s in signals)


def test_expression_injection_in_run_step_detected():
    text = """
on: issues
jobs:
  triage:
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    injections = [s for s in signals if s["rule_id"] == "nhi_github_actions_expression_injection"]
    assert len(injections) == 1
    assert injections[0]["line_number"] == 6


def test_expression_injection_multiline_run_block_detected():
    text = """
jobs:
  triage:
    steps:
      - run: |
          echo start
          echo "${{ github.head_ref }}"
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert any(s["rule_id"] == "nhi_github_actions_expression_injection" for s in signals)


def test_expression_in_with_or_env_block_not_flagged():
    text = """
jobs:
  triage:
    steps:
      - uses: some/action@1111111111111111111111111111111111111111
        with:
          title: ${{ github.event.issue.title }}
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.pull_request.title }}
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_github_actions_expression_injection" for s in signals)


def test_prt_untrusted_checkout_detected():
    text = """
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    prt = [s for s in signals if s["rule_id"] == "nhi_github_actions_prt_untrusted_checkout"]
    assert len(prt) == 1
    assert prt[0]["confidence"] == "high"


def test_prt_without_head_checkout_not_flagged_for_checkout():
    text = """
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_github_actions_prt_untrusted_checkout" for s in signals)


def test_self_hosted_runner_detected():
    text = """
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux]
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert any(s["rule_id"] == "nhi_github_actions_self_hosted_runner" for s in signals)


def test_secrets_inherit_detected():
    text = """
jobs:
  call:
    uses: org/repo/.github/workflows/deploy.yml@1111111111111111111111111111111111111111
    secrets: inherit
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert any(s["rule_id"] == "nhi_github_actions_secrets_inherit" for s in signals)


def test_deploy_token_comment_without_secrets_not_flagged():
    text = """
jobs:
  docs:
    steps:
      # the deploy step uses GITHUB_TOKEN
      - run: echo build docs
"""
    signals = github_actions.parse(Path(".github/workflows/ci.yml"), text)
    assert not any(s["rule_id"] == "nhi_ci_deployment_without_approval" for s in signals)


def test_deploy_secret_reference_flagged_high_confidence():
    text = """
jobs:
  deploy:
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}
"""
    signals = github_actions.parse(Path(".github/workflows/deploy.yml"), text)
    deploys = [s for s in signals if s["rule_id"] == "nhi_ci_deployment_without_approval"]
    assert len(deploys) == 1
    assert deploys[0]["confidence"] == "high"


def test_gated_deployment_emits_no_deploy_token_signal():
    text = """
jobs:
  deploy:
    environment:
      name: production
      reviewers: [ops-team]
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}
"""
    signals = github_actions.parse(Path(".github/workflows/deploy.yml"), text)
    assert not any(s["rule_id"] == "nhi_ci_deployment_without_approval" for s in signals)
    assert not any(
        s["rule_id"] == "nhi_environment_isolation_failure" and s["name"] == "CI/CD deployment identity"
        for s in signals
    )
