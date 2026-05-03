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
