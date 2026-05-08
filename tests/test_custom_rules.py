import json
from pathlib import Path

from greynoc_nhi.engine import normalize_signal
from greynoc_nhi.custom_rules import load_rule_pack, scan_custom_rules
from greynoc_nhi.rules import run_rules


def test_load_rule_pack_rejects_invalid_and_redos_patterns(tmp_path):
    rule_pack = tmp_path / "rules.json"
    rule_pack.write_text(
        json.dumps(
            {
                "rules": [
                    {"id": "safe", "pattern": r"GNOC_FAKE_SECRET_DO_NOT_USE_[A-Z0-9_]+", "title": "Safe"},
                    {"id": "redos", "pattern": r"(a+)+$"},
                    {"id": "invalid", "pattern": r"(["},
                    {"id": "bad_severity", "pattern": r"GNOC_FAKE_SECRET_DO_NOT_USE_[A-Z0-9_]+", "severity": "urgent"},
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_rule_pack(rule_pack)

    assert [rule.id for rule in rules] == ["safe"]
    signals = scan_custom_rules(
        Path("fixture.env"),
        "TOKEN=GNOC_FAKE_SECRET_DO_NOT_USE_CUSTOM_RULE_123456",
        rules,
    )
    assert [signal["rule_id"] for signal in signals] == ["safe"]


def test_load_rule_pack_ignores_missing_or_malformed_files(tmp_path):
    malformed = tmp_path / "bad.json"
    malformed.write_text("{", encoding="utf-8")

    assert load_rule_pack(tmp_path / "missing.json") == []
    assert load_rule_pack(malformed) == []


def test_structural_custom_rule_matches_identity_without_secret_like_regex(tmp_path):
    rule_pack = tmp_path / "rules.json"
    rule_pack.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom_ai_agent_shell_no_approval",
                        "type": "structural",
                        "when": {
                            "identity_type": "ai_agent",
                            "tools_contains_any": ["shell", "terminal"],
                            "approval_required": False,
                        },
                        "severity": "critical",
                        "title": "AI agent can run shell without approval",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_rule_pack(rule_pack)
    identity = normalize_signal(
        {
            "rule_id": "nhi_ai_agent_shell_access",
            "file_path": "agents.json",
            "line_number": 1,
            "name": "agent",
            "identity_type": "ai_agent",
            "source": "test",
            "evidence": ["tools: shell"],
            "tools": ["shell"],
            "approval_required": False,
            "tags": ["ai_agent"],
        }
    )

    findings = run_rules(
        [identity],
        {
            rule.id: {
                "title": rule.title,
                "severity": rule.severity,
                "type": rule.type,
                "when": rule.when,
                "remediation": rule.remediation,
            }
            for rule in rules
        },
    )

    assert any(finding.rule_id == "custom_ai_agent_shell_no_approval" for finding in findings)
