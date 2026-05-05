"""Custom local JSON rule-pack support."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from greynoc_nhi.confidence import normalize_confidence
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal


@dataclass(frozen=True)
class CustomRule:
    id: str
    title: str
    severity: str
    pattern: str
    identity_type: str
    provider: str | None
    remediation: str
    confidence: str


def load_rule_pack(path: str | Path | None) -> list[CustomRule]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = data.get("rules", []) if isinstance(data, dict) else []
    loaded: list[CustomRule] = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("id") or not rule.get("pattern"):
            continue
        loaded.append(
            CustomRule(
                id=str(rule["id"]),
                title=str(rule.get("title", rule["id"])),
                severity=str(rule.get("severity", "medium")).lower(),
                pattern=str(rule["pattern"]),
                identity_type=str(rule.get("identity_type", "custom token")),
                provider=str(rule["provider"]) if rule.get("provider") else None,
                remediation=str(rule.get("remediation", "Review, rotate if real, and move this value into a managed secret store.")),
                confidence=normalize_confidence(rule.get("confidence")),
            )
        )
    return loaded


def scan_custom_rules(path: Path, text: str, rules: list[CustomRule]) -> list[Signal]:
    signals: list[Signal] = []
    if not rules:
        return signals
    for number, line in enumerate(text.splitlines(), 1):
        for rule in rules:
            for match in re.finditer(rule.pattern, line):
                value = match.group(0)
                if not looks_like_secret(value):
                    continue
                signals.append(
                    make_signal(
                        rule_id=rule.id,
                        file_path=path,
                        line_number=number,
                        name=rule.title,
                        identity_type=rule.identity_type,
                        source="custom rule pack",
                        evidence=line.strip(),
                        secret_value=value,
                        provider=rule.provider,
                        external_access=True,
                        tags=["custom_rule", "plaintext_secret", rule.id],
                        confidence=rule.confidence,
                    )
                )
    return signals


def custom_rule_templates(rules: list[CustomRule]) -> dict[str, dict[str, Any]]:
    return {
        rule.id: {
            "title": rule.title,
            "severity": rule.severity,
            "remediation": rule.remediation,
            "confidence": rule.confidence,
        }
        for rule in rules
    }
