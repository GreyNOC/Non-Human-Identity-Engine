"""Tests for the Renovate / Dependabot bot config parser."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi.parsers import bot_configs


def test_should_parse_relevant_files() -> None:
    assert bot_configs.should_parse(Path("renovate.json")) is True
    assert bot_configs.should_parse(Path(".renovaterc")) is True
    assert bot_configs.should_parse(Path(".github/dependabot.yml")) is True
    assert bot_configs.should_parse(Path("README.md")) is False


def test_renovate_records_bot_inventory() -> None:
    text = json.dumps({"extends": ["config:base"]})
    signals = bot_configs.parse(Path("renovate.json"), text)
    assert any(s["rule_id"] == "nhi_renovate_bot_identity" for s in signals)


def test_renovate_detects_automerge() -> None:
    text = json.dumps({"automerge": True, "extends": ["config:base"]})
    signals = bot_configs.parse(Path("renovate.json"), text)
    assert any(s["rule_id"] == "nhi_renovate_automerge_enabled" for s in signals)


def test_renovate_detects_plaintext_token() -> None:
    text = json.dumps(
        {
            "hostRules": [
                {
                    "matchHost": "registry.example.com",
                    "token": "GNOC_FAKE_SECRET_DO_NOT_USE_RENO_998877",
                }
            ]
        }
    )
    signals = bot_configs.parse(Path("renovate.json"), text)
    assert any(s["rule_id"] == "nhi_renovate_host_rules_plaintext_token" for s in signals)


def test_renovate_detects_extends_github_preset() -> None:
    text = json.dumps({"extends": ["github>some-user/renovate-preset"]})
    signals = bot_configs.parse(Path("renovate.json"), text)
    assert any(s["rule_id"] == "nhi_renovate_extends_github_preset" for s in signals)


def test_renovate_detects_disabled_vulnerability_alerts() -> None:
    text = json.dumps({"vulnerabilityAlerts": {"enabled": False}})
    signals = bot_configs.parse(Path("renovate.json"), text)
    assert any(s["rule_id"] == "nhi_renovate_vulnerability_alerts_disabled" for s in signals)


def test_renovate_json5_with_comments_and_trailing_commas_is_parsed() -> None:
    text = """{
  // Managed by platform team
  "extends": ["config:recommended"],
  /* enable automerge for devDependencies */
  "automerge": true,
  "hostRules": [
    {
      "matchHost": "registry.example.com",
      "token": "GNOC_FAKE_SECRET_DO_NOT_USE_RENO5_998877", // rotate quarterly
    },
  ],
}
"""
    signals = bot_configs.parse(Path("renovate.json5"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_renovate_bot_identity" in rule_ids
    assert "nhi_renovate_automerge_enabled" in rule_ids
    assert "nhi_renovate_host_rules_plaintext_token" in rule_ids
    token = next(s for s in signals if s["rule_id"] == "nhi_renovate_host_rules_plaintext_token")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_RENO5_998877" not in " ".join(token["evidence"])


def test_renovate_json5_urls_survive_comment_stripping() -> None:
    text = """{
  // registry configuration
  "registryUrls": ["https://registry.example.com/api/npm/"],
  "extends": ["config:recommended"],
}
"""
    signals = bot_configs.parse(Path("renovate.json5"), text)
    assert any(s["rule_id"] == "nhi_renovate_bot_identity" for s in signals)


def test_renovate_unparseable_config_still_records_identity_and_automerge() -> None:
    text = "{ this is not json5 at all\nautomerge: true\n"
    signals = bot_configs.parse(Path("renovate.json5"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_renovate_bot_identity" in rule_ids
    assert "nhi_renovate_automerge_enabled" in rule_ids


def test_dependabot_records_bot_inventory() -> None:
    text = """
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
"""
    signals = bot_configs.parse(Path(".github/dependabot.yml"), text)
    assert any(s["rule_id"] == "nhi_dependabot_bot_identity" for s in signals)


def test_dependabot_targets_main_branch() -> None:
    text = """
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    target-branch: main
    schedule:
      interval: "weekly"
"""
    signals = bot_configs.parse(Path(".github/dependabot.yml"), text)
    assert any(s["rule_id"] == "nhi_dependabot_targets_protected_branch" for s in signals)
