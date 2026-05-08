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


# Hard caps on user-supplied patterns. The stdlib `re` module has no timeout,
# so a malicious or careless rule pack can hang every CI scan with a classic
# ReDoS shape like `(a+)+$` (confirmed: ~88s on 30 chars in testing). Reject
# anything that looks dangerous at load time rather than at scan time.
_MAX_PATTERN_LENGTH = 512
_REDOS_SHAPES = re.compile(
    r"\([^)]*[+*][^)]*\)[+*?]"  # nested unbounded quantifier: (a+)+, (.*)*, (x+)?
    r"|"
    r"\([^)]*\|[^)]*\)[+*]"  # alternation under unbounded quantifier: (a|a)+
)


@dataclass(frozen=True)
class CustomRule:
    id: str
    title: str
    severity: str
    type: str
    pattern: str | None
    compiled: re.Pattern[str] | None
    when: dict[str, Any]
    identity_type: str
    provider: str | None
    remediation: str
    confidence: str


def _safe_compile(pattern: str) -> re.Pattern[str] | None:
    """Compile a user-supplied pattern, or return None if unsafe/invalid."""
    if not isinstance(pattern, str) or not pattern:
        return None
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    if _REDOS_SHAPES.search(pattern):
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def load_rule_pack(path: str | Path | None) -> list[CustomRule]:
    if not path:
        return []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rules = data.get("rules", []) if isinstance(data, dict) else []
    loaded: list[CustomRule] = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        rule_type = str(rule.get("type", "regex")).lower()
        pattern = str(rule["pattern"]) if rule.get("pattern") else None
        compiled = _safe_compile(pattern) if pattern else None
        when = rule.get("when", {}) if isinstance(rule.get("when", {}), dict) else {}
        if rule_type == "structural":
            if not when:
                continue
        elif compiled is None:
            continue
        loaded.append(
            CustomRule(
                id=str(rule["id"]),
                title=str(rule.get("title", rule["id"])),
                severity=str(rule.get("severity", "medium")).lower(),
                type=rule_type,
                pattern=pattern,
                compiled=compiled,
                when=when,
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
            if rule.type == "structural" or rule.compiled is None:
                continue
            for match in rule.compiled.finditer(line):
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
            "type": rule.type,
            "when": rule.when,
        }
        for rule in rules
    }
