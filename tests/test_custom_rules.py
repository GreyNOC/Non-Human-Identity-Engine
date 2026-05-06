import json
from pathlib import Path

from greynoc_nhi.custom_rules import load_rule_pack, scan_custom_rules


def test_load_rule_pack_rejects_invalid_and_redos_patterns(tmp_path):
    rule_pack = tmp_path / "rules.json"
    rule_pack.write_text(
        json.dumps(
            {
                "rules": [
                    {"id": "safe", "pattern": r"GNOC_FAKE_SECRET_DO_NOT_USE_[A-Z0-9_]+", "title": "Safe"},
                    {"id": "redos", "pattern": r"(a+)+$"},
                    {"id": "invalid", "pattern": r"(["},
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
