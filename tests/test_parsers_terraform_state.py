"""Tests for the Terraform state file parser."""

from __future__ import annotations

import json
from pathlib import Path

from greynoc_nhi.parsers import terraform_state
from greynoc_nhi.scanner import Scanner


def test_should_parse_matches_state_files() -> None:
    assert terraform_state.should_parse(Path("terraform.tfstate")) is True
    assert terraform_state.should_parse(Path("terraform.tfstate.backup")) is True
    assert terraform_state.should_parse(Path("main.tf")) is False


def test_state_parser_finds_aws_iam_secret() -> None:
    state = {
        "version": 4,
        "resources": [
            {
                "type": "aws_iam_access_key",
                "instances": [
                    {
                        "attributes": {
                            "id": "AKIAIOSFODNN7EXAMPLE",
                            "secret": "wJalrXUtnFEMI/K7MDENG/GNOC_FAKE_SECRET_DO_NOT_USE",
                        }
                    }
                ],
            }
        ],
    }
    signals = terraform_state.parse(Path("terraform.tfstate"), json.dumps(state, indent=2))
    assert any(s["rule_id"] == "nhi_terraform_state_plaintext_secret" for s in signals)
    found = signals[0]
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in found["evidence"][0]
    assert found["provider"] == "aws"


def test_state_parser_skips_non_secret_keys() -> None:
    state = {"resources": [{"name": "Just a name", "tags": {"env": "production"}}]}
    signals = terraform_state.parse(Path("terraform.tfstate"), json.dumps(state))
    assert signals == []


def test_state_parser_skips_non_json() -> None:
    assert terraform_state.parse(Path("terraform.tfstate"), "not json at all") == []


def test_scanner_picks_up_tfstate_files(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    state_path = project / "terraform.tfstate"
    state = {
        "resources": [
            {
                "type": "aws_db_instance",
                "instances": [
                    {"attributes": {"password": "GNOC_FAKE_SECRET_DO_NOT_USE_DB_998877"}}
                ],
            }
        ]
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    raw = Scanner().scan(project)
    assert raw["scanned_files"] == 1
    assert any(s["rule_id"] == "nhi_terraform_state_plaintext_secret" for s in raw["signals"])
