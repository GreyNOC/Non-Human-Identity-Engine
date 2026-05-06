"""Scan orchestration engine."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from greynoc_nhi.advanced import synthesize_advanced_signals
from greynoc_nhi.baseline import apply_baseline
from greynoc_nhi.confidence import normalize_confidence
from greynoc_nhi.custom_rules import custom_rule_templates
from greynoc_nhi.masking import fingerprint_secret, mask_secret, redact_inline_secret
from greynoc_nhi.models import Finding, NonHumanIdentity, ScanResult
from greynoc_nhi.rules import run_rules
from greynoc_nhi.scanner import Scanner
from greynoc_nhi.scoring import calculate_overall_score, severity_label
from greynoc_nhi.storage import Storage
from greynoc_nhi.utils import stable_id, utc_now

TRUE_STRINGS = {"1", "true", "yes", "y", "on", "enabled"}
FALSE_STRINGS = {"0", "false", "no", "n", "off", "disabled", "none", "null", ""}

SUPPORTED_IDENTITY_TYPES = {
    "ai_agent",
    "mcp_server",
    "model_gateway",
    "tool_connector",
    "oauth_app",
    "browser_extension",
    "ci_runner",
    "webhook_identity",
    "service_account",
    "cloud_workload_identity",
    "api_key",
    "bot_account",
    "deployment_identity",
}

IDENTITY_TYPE_ALIASES = {
    "ai agent tool connector": "ai_agent",
    "ai_agent tool connector": "ai_agent",
    "ai agent": "ai_agent",
    "mcp server connector": "mcp_server",
    "mcp connector": "mcp_server",
    "oauth application": "oauth_app",
    "oauth app": "oauth_app",
    "browser extension identity": "browser_extension",
    "browser extension": "browser_extension",
    "ci/cd secret": "ci_runner",
    "ci_cd secret": "ci_runner",
    "ci_cd_secret": "ci_runner",
    "ci runner": "ci_runner",
    "github actions workflow token": "ci_runner",
    "webhook secret": "webhook_identity",
    "webhook url": "webhook_identity",
    "service account": "service_account",
    "cloud iam user": "cloud_workload_identity",
    "cloud iam role": "cloud_workload_identity",
    "cloud workload identity": "cloud_workload_identity",
    "api key": "api_key",
    "github token": "api_key",
    "package registry token": "api_key",
    "bot account": "bot_account",
    "deployment token": "deployment_identity",
    "deployment identity": "deployment_identity",
    "automation script credential": "deployment_identity",
}


def normalize_bool(value: object, default: bool | None = False) -> bool | None:
    """Parse booleans without treating strings like "false" as truthy."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in TRUE_STRINGS:
        return True
    if normalized in FALSE_STRINGS:
        return False
    return default


def normalize_string_list(value: object) -> list[str]:
    """Normalize list-like parser fields while redacting accidental secrets."""
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for key, item in value.items():
            if isinstance(item, (list, tuple, set, dict)):
                for nested in normalize_string_list(item):
                    values.append(f"{key}:{nested}")
            else:
                values.append(f"{key}:{item}")
        return _dedupe_redacted(values)
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(normalize_string_list(item))
        return _dedupe_redacted(values)
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            return normalize_string_list(parsed)
    parts = [part.strip().strip("'\"") for part in re.split(r"[,;\n]+|\s{2,}", text)]
    if len(parts) == 1 and " " in parts[0] and not any(separator in parts[0] for separator in [":\\", "/", "\\"]):
        parts = [part.strip().strip("'\"") for part in parts[0].split()]
    return _dedupe_redacted(parts)


def _dedupe_redacted(values: list[object]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = redact_inline_secret(str(value).strip())
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _safe_text(value: object | None, secret_value: object | None = None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if secret_value:
        text = text.replace(str(secret_value), mask_secret(str(secret_value)))
    return redact_inline_secret(text)


def _safe_evidence(value: object, secret_value: object | None = None) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [item for item in (_safe_text(item, secret_value) for item in values) if item]


def _line_number(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def canonical_identity_type(value: object | None) -> str:
    raw = str(value or "non_human_identity").strip()
    lowered = raw.replace("-", "_").replace("/", "_").lower()
    lowered = re.sub(r"\s+", " ", lowered)
    if lowered in SUPPORTED_IDENTITY_TYPES:
        return lowered
    if lowered in IDENTITY_TYPE_ALIASES:
        return IDENTITY_TYPE_ALIASES[lowered]
    slug = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return IDENTITY_TYPE_ALIASES.get(slug, slug or "non_human_identity")


def normalize_signal(signal: dict) -> NonHumanIdentity:
    """Convert parser signal dictionaries into safe NHI model objects."""
    secret_value = signal.get("secret_value")
    tags = sorted(set(item for item in [signal.get("rule_id"), *normalize_string_list(signal.get("tags"))] if item))
    secret_fingerprint = fingerprint_secret(secret_value) if secret_value else None
    masked_secret = mask_secret(secret_value) if secret_value else None
    file_path = _safe_text(signal.get("file_path"))
    line_number = _line_number(signal.get("line_number"))
    permissions = normalize_string_list(signal.get("permissions"))
    scopes = normalize_string_list(signal.get("scopes"))
    tools = normalize_string_list(signal.get("tools"))
    tool_permissions = normalize_string_list(signal.get("tool_permissions")) or tools
    data_classes = normalize_string_list(signal.get("data_classes"))
    return NonHumanIdentity(
        id=stable_id("nhi", signal.get("file_path"), signal.get("line_number"), signal.get("name"), signal.get("rule_id"), secret_fingerprint or ""),
        name=_safe_text(signal.get("name"), secret_value) or "Unknown NHI",
        identity_type=canonical_identity_type(signal.get("identity_type")),
        source=_safe_text(signal.get("source")) or "scanner",
        file_path=file_path,
        line_number=line_number,
        source_file=file_path,
        source_line=line_number,
        owner=_safe_text(signal.get("owner")),
        business_purpose=_safe_text(signal.get("business_purpose")),
        environment=_safe_text(signal.get("environment")),
        provider=_safe_text(signal.get("provider")),
        expires_at=_safe_text(signal.get("expires_at")),
        review_due_date=_safe_text(signal.get("review_due_date")),
        revocation_hint=_safe_text(signal.get("revocation_hint")),
        secret_age_days=signal.get("secret_age_days"),
        permissions=permissions,
        scopes=scopes,
        tools=tools,
        tool_permissions=tool_permissions,
        data_classes=data_classes,
        has_secret=bool(secret_value or "plaintext_secret" in tags),
        secret_fingerprint=secret_fingerprint,
        masked_secret=masked_secret,
        admin_access=bool(normalize_bool(signal.get("admin_access"), False)),
        production_access=bool(normalize_bool(signal.get("production_access"), False)),
        external_access=bool(normalize_bool(signal.get("external_access"), False)),
        data_access_level=_safe_text(signal.get("data_access_level")) or "unknown",
        logging_enabled=normalize_bool(signal.get("logging_enabled"), None),
        rotation_status=signal.get("rotation_status", "missing") if secret_value else signal.get("rotation_status"),
        approval_required=normalize_bool(signal.get("approval_required"), None),
        context_store=_safe_text(signal.get("context_store"), secret_value),
        memory_enabled=normalize_bool(signal.get("memory_enabled"), None),
        evidence=_safe_evidence(signal.get("evidence", []), secret_value),
        raw_reference=_safe_text(signal.get("raw_reference"), secret_value),
        tags=tags,
        related_identities=normalize_string_list(signal.get("related_identities")),
        confidence=normalize_confidence(signal.get("confidence")),
        commit_sha=_safe_text(signal.get("commit_sha")),
        commit_short_sha=_safe_text(signal.get("commit_short_sha")),
        commit_author=_safe_text(signal.get("commit_author")),
        commit_date=_safe_text(signal.get("commit_date")),
    )


class Engine:
    """Runs scan, rule evaluation, scoring, and optional persistence."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        rule_pack_path: str | Path | None = None,
        allow_untrusted_persist: bool = False,
    ) -> None:
        self.scanner = Scanner(rule_pack_path=rule_pack_path)
        self.storage = Storage(db_path) if db_path else None
        self.allow_untrusted_persist = allow_untrusted_persist

    def run_scan(
        self,
        project_path: str | Path,
        persist: bool = True,
        baseline_path: str | Path | None = None,
        allow_untrusted_persist: bool | None = None,
        *,
        scan_history: bool = False,
        history_max_commits: int | None = 1000,
        history_since: str | None = None,
        history_only: bool = False,
    ) -> ScanResult:
        started = utc_now()
        correlation_id = str(uuid4())
        fatal_errors: list[str] = []
        if history_only and not scan_history:
            scan_history = True
        if history_only:
            raw = {
                "project_path": str(Path(project_path).resolve()),
                "signals": [],
                "errors": [],
                "scanned_files": 0,
                "skipped_files": 0,
                "ignore_patterns": [],
                "custom_rules": [],
            }
        else:
            try:
                raw = self.scanner.scan(project_path)
            except Exception as exc:
                raw = {
                    "project_path": str(Path(project_path).resolve()),
                    "signals": [],
                    "errors": [],
                    "scanned_files": 0,
                    "skipped_files": 0,
                    "ignore_patterns": [],
                    "custom_rules": [],
                }
                fatal_errors.append(f"scanner failure: {redact_inline_secret(str(exc))}")
        history_stats: dict[str, Any] = {"enabled": False, "commits_scanned": 0, "history_signals": 0}
        if scan_history:
            history_stats["enabled"] = True
            try:
                history_raw = self.scanner.scan_history(
                    project_path,
                    max_commits=history_max_commits,
                    since=history_since,
                )
            except Exception as exc:
                fatal_errors.append(f"history scan failure: {redact_inline_secret(str(exc))}")
                history_raw = {"signals": [], "errors": [], "commits_scanned": 0}
            history_stats["commits_scanned"] = history_raw.get("commits_scanned", 0)
            history_stats["history_signals"] = len(history_raw.get("signals", []))
            raw["signals"] = list(raw.get("signals", [])) + list(history_raw.get("signals", []))
            raw["errors"] = list(raw.get("errors", [])) + list(history_raw.get("errors", []))

        identities: list[NonHumanIdentity] = []
        normalization_errors: list[dict[str, str]] = []
        for signal in raw.get("signals", []):
            try:
                identities.append(normalize_signal(signal))
            except Exception as exc:
                normalization_errors.append({"signal": redact_inline_secret(str(signal.get("rule_id", "unknown"))), "error": redact_inline_secret(str(exc))})

        advanced_signals: list[dict[str, Any]] = []
        if not fatal_errors:
            try:
                advanced_signals = synthesize_advanced_signals(identities, raw)
                for signal in advanced_signals:
                    identities.append(normalize_signal(signal))
            except Exception as exc:
                fatal_errors.append(f"advanced correlation failure: {redact_inline_secret(str(exc))}")

        findings: list[Finding] = []
        if not fatal_errors:
            try:
                findings = run_rules(identities, custom_rule_templates(raw.get("custom_rules", [])))
            except Exception as exc:
                fatal_errors.append(f"rule evaluation failure: {redact_inline_secret(str(exc))}")

        parser_errors = [
            {key: redact_inline_secret(value) for key, value in error.items()}
            for error in raw.get("errors", [])
        ]
        overall = 100 if fatal_errors else calculate_overall_score(identities, findings)
        completed = utc_now()
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        scan_trust_level = _scan_trust_level(fatal_errors, parser_errors, normalization_errors, findings)
        policy_decision = _policy_decision(scan_trust_level, findings)
        if fatal_errors:
            summary = (
                "Scan could not be trusted because the engine encountered a fatal execution error. "
                "Treat this result as blocked until the scan can complete cleanly."
            )
        elif parser_errors or normalization_errors:
            summary = (
                f"Scan completed in a degraded state with {len(parser_errors) + len(normalization_errors)} parser or normalization errors. "
                "Review the errors before treating missing findings as clean."
            )
        elif findings:
            top = findings[0]
            summary = (
                f"Your project has {critical} critical and {high} high NHI findings. "
                f"The highest-risk issue is: {top.title}. Fix this before production release."
            )
        else:
            summary = "No high-confidence NHI risks were found in the scanned files."
        result = ScanResult(
            scan_id=stable_id("scan", raw["project_path"], started, len(identities), len(findings)),
            project_path=raw["project_path"],
            started_at=started,
            completed_at=completed,
            identities=identities,
            findings=findings,
            overall_score=overall,
            summary=summary,
            stats={
                "scanned_files": raw["scanned_files"],
                "skipped_files": raw["skipped_files"],
                "parser_errors": parser_errors,
                "normalization_errors": normalization_errors,
                "advanced_correlations": len(advanced_signals),
                "custom_rules_loaded": len(raw.get("custom_rules", [])),
                "severity_label": severity_label(overall),
                "critical_findings": critical,
                "high_findings": high,
                "identities_found": len(identities),
                "findings_count": len(findings),
                "scan_trust_level": scan_trust_level,
                "policy_decision": policy_decision,
                "fatal_errors": fatal_errors,
                "correlation_id": correlation_id,
                "history": history_stats,
            },
            scan_trust_level=scan_trust_level,
            policy_decision=policy_decision,
            fatal_errors=fatal_errors,
            correlation_id=correlation_id,
        )
        if baseline_path:
            apply_baseline(result, baseline_path)
        allow_untrusted = self.allow_untrusted_persist if allow_untrusted_persist is None else allow_untrusted_persist
        if persist and self.storage and (result.scan_trust_level != "untrusted" or allow_untrusted):
            self.storage.save_scan(result)
        return result


def _scan_trust_level(
    fatal_errors: list[str],
    parser_errors: list[dict[str, str]],
    normalization_errors: list[dict[str, str]],
    findings: list[Finding],
) -> str:
    if fatal_errors:
        return "untrusted"
    if parser_errors or normalization_errors:
        return "degraded"
    if any(finding.severity in {"critical", "high"} for finding in findings):
        return "action_required"
    return "clean"


def _policy_decision(scan_trust_level: str, findings: list[Finding]) -> str:
    if scan_trust_level == "untrusted" or any(finding.severity == "critical" for finding in findings):
        return "block"
    if scan_trust_level in {"degraded", "action_required"} or any(finding.severity == "high" for finding in findings):
        return "manual_review"
    return "pass"
