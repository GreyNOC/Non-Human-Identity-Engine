"""Renovate and Dependabot configuration parser.

Both bots write to your repository (open PRs, push branches, sometimes
auto-merge). Their config files describe a *bot identity* whose permissions
the repo has implicitly granted, so they are NHIs in their own right.

Risks the parser surfaces:

* Plaintext tokens in Renovate `hostRules`
* `automerge: true` (especially without restricting `automergeType`)
* `vulnerabilityAlerts: enabled: false` (disabled security updates)
* Inventory of the Dependabot bot identity itself, so reports can list it
"""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for, line_number_for_key_value, parse_json_safely

RENOVATE_FILES = {
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
}
DEPENDABOT_FILES = {"dependabot.yml", "dependabot.yaml"}

# JSON5-lite normalization: Renovate templates its .json5 configs with //
# comments and trailing commas, which strict json.loads rejects outright.
_JSON5_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_JSON5_FULL_LINE_COMMENT_RE = re.compile(r"(?m)^\s*//.*$")
# Only strip trailing // comments preceded by structural characters or
# whitespace and with no quote before end-of-line, so URLs ("https://...")
# and quoted values containing // survive.
_JSON5_TRAILING_COMMENT_RE = re.compile(r"(?m)(?<=[\s{}\[\],])//[^\"'\n]*$")
_JSON5_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_FALLBACK_TOKEN_RE = re.compile(r"\btoken\b\s*[:=]\s*['\"]?([^'\"\s,]+)", re.I)
_FALLBACK_AUTOMERGE_RE = re.compile(r"\bautomerge\b\s*[:=]\s*true", re.I)


def _parse_json5_lite(text: str):
    """Strict parse first; on failure retry after best-effort JSON5 cleanup."""
    data = parse_json_safely(text)
    if data is not None:
        return data
    cleaned = _JSON5_BLOCK_COMMENT_RE.sub("", text)
    cleaned = _JSON5_FULL_LINE_COMMENT_RE.sub("", cleaned)
    cleaned = _JSON5_TRAILING_COMMENT_RE.sub("", cleaned)
    cleaned = _JSON5_TRAILING_COMMA_RE.sub(r"\1", cleaned)
    return parse_json_safely(cleaned)


def _parse_renovate_fallback(path: Path, text: str) -> list[Signal]:
    """Line-level extraction when even JSON5-lite normalization fails."""
    signals: list[Signal] = []
    lowered = text.lower()
    if "hostrules" in lowered:
        for number, line in enumerate(text.splitlines(), 1):
            match = _FALLBACK_TOKEN_RE.search(line)
            if not match:
                continue
            value = match.group(1)
            if value and not value.startswith("$") and looks_like_secret(value):
                signals.append(
                    make_signal(
                        rule_id="nhi_renovate_host_rules_plaintext_token",
                        file_path=path,
                        line_number=number,
                        name="Renovate hostRules token",
                        identity_type="bot_account",
                        source="renovate",
                        evidence=line.strip(),
                        secret_value=value,
                        provider="renovate",
                        external_access=True,
                        tags=["renovate", "bot_credential", "plaintext_secret"],
                        confidence="high",
                    )
                )
    if _FALLBACK_AUTOMERGE_RE.search(text):
        signals.append(
            make_signal(
                rule_id="nhi_renovate_automerge_enabled",
                file_path=path,
                line_number=line_number_for(text, "automerge"),
                name="Renovate automerge enabled",
                identity_type="bot_account",
                source="renovate",
                evidence="automerge: true",
                provider="renovate",
                permissions=["contents:write", "pull-requests:write", "merge"],
                external_access=True,
                production_access=True,
                tags=["renovate", "bot_credential", "automerge"],
            )
        )
    if text.strip():
        signals.append(
            make_signal(
                rule_id="nhi_renovate_bot_identity",
                file_path=path,
                line_number=1,
                name="Renovate bot",
                identity_type="bot_account",
                source="renovate",
                evidence="Renovate config grants the Renovate bot write access to this repository",
                provider="renovate",
                permissions=["contents:write", "pull-requests:write"],
                external_access=True,
                tags=["renovate", "bot_credential", "inventory"],
                confidence="high",
            )
        )
    return signals


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    normalized = str(path).replace("\\", "/").lower()
    if name in RENOVATE_FILES:
        return True
    if name in DEPENDABOT_FILES and (".github/" in normalized or normalized.endswith("dependabot.yml") or normalized.endswith("dependabot.yaml")):
        return True
    return False


def _parse_renovate(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    data = _parse_json5_lite(text)
    if data is None:
        return _parse_renovate_fallback(path, text)
    flat = flatten_json(data)
    for key, value in flat:
        if isinstance(value, str) and key.endswith(".token") and "hostrules" in key.lower():
            if value and not value.startswith("$") and looks_like_secret(value):
                signals.append(
                    make_signal(
                        rule_id="nhi_renovate_host_rules_plaintext_token",
                        file_path=path,
                        line_number=line_number_for_key_value(text, key, value),
                        name="Renovate hostRules token",
                        identity_type="bot_account",
                        source="renovate",
                        evidence=f"{key}={value}",
                        secret_value=value,
                        provider="renovate",
                        external_access=True,
                        tags=["renovate", "bot_credential", "plaintext_secret"],
                        confidence="high",
                    )
                )
    automerge_count = sum(1 for k, v in flat if k.endswith(".automerge") and v is True or k == "automerge" and v is True)
    if automerge_count:
        signals.append(
            make_signal(
                rule_id="nhi_renovate_automerge_enabled",
                file_path=path,
                line_number=line_number_for(text, "automerge"),
                name="Renovate automerge enabled",
                identity_type="bot_account",
                source="renovate",
                evidence=f"automerge: true (in {automerge_count} location(s))",
                provider="renovate",
                permissions=["contents:write", "pull-requests:write", "merge"],
                external_access=True,
                production_access=True,
                tags=["renovate", "bot_credential", "automerge"],
            )
        )
    if any(k == "vulnerabilityAlerts.enabled" and v is False for k, v in flat):
        signals.append(
            make_signal(
                rule_id="nhi_renovate_vulnerability_alerts_disabled",
                file_path=path,
                line_number=line_number_for(text, "vulnerabilityAlerts"),
                name="Renovate vulnerability alerts disabled",
                identity_type="bot_account",
                source="renovate",
                evidence='"vulnerabilityAlerts": { "enabled": false }',
                provider="renovate",
                tags=["renovate", "bot_credential", "security_disabled"],
            )
        )
    for k, v in flat:
        if isinstance(v, str) and v.startswith("github>") and "extends" in k:
            signals.append(
                make_signal(
                    rule_id="nhi_renovate_extends_github_preset",
                    file_path=path,
                    line_number=line_number_for(text, v),
                    name=f"Renovate extends preset {v}",
                    identity_type="bot_account",
                    source="renovate",
                    evidence=f"extends: {v}",
                    provider="renovate",
                    external_access=True,
                    tags=["renovate", "bot_credential", "external_preset"],
                    confidence="medium",
                )
            )
            break
    if signals or data:
        signals.append(
            make_signal(
                rule_id="nhi_renovate_bot_identity",
                file_path=path,
                line_number=1,
                name="Renovate bot",
                identity_type="bot_account",
                source="renovate",
                evidence="Renovate config grants the Renovate bot write access to this repository",
                provider="renovate",
                permissions=["contents:write", "pull-requests:write"],
                external_access=True,
                tags=["renovate", "bot_credential", "inventory"],
                confidence="high",
            )
        )
    return signals


def _parse_dependabot(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    if "version: 2" not in text and not re.search(r"^\s*updates\s*:", text, re.MULTILINE):
        return signals
    line_no = next((n for n, ln in enumerate(text.splitlines(), 1) if "package-ecosystem" in ln), 1)
    signals.append(
        make_signal(
            rule_id="nhi_dependabot_bot_identity",
            file_path=path,
            line_number=line_no,
            name="Dependabot",
            identity_type="bot_account",
            source="dependabot",
            evidence="Dependabot configured for this repository - has write access via app integration",
            provider="github",
            permissions=["contents:write", "pull-requests:write"],
            external_access=True,
            tags=["dependabot", "bot_credential", "inventory"],
            confidence="high",
        )
    )
    if re.search(r"^\s*target-branch\s*:\s*['\"]?(main|master|production|prod|release)", text, re.MULTILINE | re.IGNORECASE):
        target_line = next(
            (n for n, ln in enumerate(text.splitlines(), 1) if "target-branch" in ln), None
        )
        signals.append(
            make_signal(
                rule_id="nhi_dependabot_targets_protected_branch",
                file_path=path,
                line_number=target_line,
                name="Dependabot targets protected branch directly",
                identity_type="bot_account",
                source="dependabot",
                evidence="dependabot writes PRs against main/production branch",
                provider="github",
                permissions=["contents:write", "pull-requests:write"],
                external_access=True,
                production_access=True,
                tags=["dependabot", "bot_credential", "production_path"],
            )
        )
    return signals


def parse(path: Path, text: str) -> list[Signal]:
    name = path.name.lower()
    if name in RENOVATE_FILES:
        return _parse_renovate(path, text)
    if name in DEPENDABOT_FILES:
        return _parse_dependabot(path, text)
    return []
