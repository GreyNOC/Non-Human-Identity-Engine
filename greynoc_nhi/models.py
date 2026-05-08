"""Core dataclasses for GreyNOC NHI scan results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NonHumanIdentity:
    id: str
    name: str
    identity_type: str
    source: str
    file_path: str | None = None
    line_number: int | None = None
    source_file: str | None = None
    source_line: int | None = None
    owner: str | None = None
    business_purpose: str | None = None
    environment: str | None = None
    provider: str | None = None
    created_at: str | None = None
    last_used_at: str | None = None
    expires_at: str | None = None
    review_due_date: str | None = None
    revocation_hint: str | None = None
    secret_age_days: int | None = None
    permissions: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    tool_permissions: list[str] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    has_secret: bool = False
    secret_fingerprint: str | None = None
    masked_secret: str | None = None
    admin_access: bool = False
    production_access: bool = False
    external_access: bool = False
    data_access_level: str = "unknown"
    logging_enabled: bool | None = None
    rotation_status: str | None = None
    approval_required: bool | None = None
    context_store: str | None = None
    memory_enabled: bool | None = None
    ai_risk_refs: list[str] = field(default_factory=list)
    ai_attack_class: str | None = None
    attack_chain_stage: str | None = None
    evidence: list[str] = field(default_factory=list)
    raw_reference: str | None = None
    tags: list[str] = field(default_factory=list)
    related_identities: list[str] = field(default_factory=list)
    confidence: str = "medium"
    commit_sha: str | None = None
    commit_short_sha: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str
    risk_score: int
    category: str
    identity_id: str | None
    identity_name: str | None
    source: str
    file_path: str | None
    line_number: int | None
    explanation: str
    why_it_matters: str
    evidence: list[str]
    remediation: str
    priority: str
    owasp_nhi_refs: list[str]
    control_hints: list[str]
    created_at: str
    ai_risk_refs: list[str] = field(default_factory=list)
    confidence: str = "medium"
    related_identities: list[str] = field(default_factory=list)
    baseline_status: str = "new"
    baseline_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskPath:
    id: str
    source: str
    agent: str | None
    tool: str | None
    credential: str | None
    sink: str
    trust_boundary: str
    attack_class: str
    evidence: list[str]
    related_identities: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    project_path: str
    started_at: str
    completed_at: str
    identities: list[NonHumanIdentity]
    findings: list[Finding]
    overall_score: int
    summary: str
    stats: dict[str, Any]
    risk_paths: list[RiskPath] = field(default_factory=list)
    scan_trust_level: str = "clean"
    policy_decision: str = "pass"
    fatal_errors: list[str] = field(default_factory=list)
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "project_path": self.project_path,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "identities": [identity.to_dict() for identity in self.identities],
            "findings": [finding.to_dict() for finding in self.findings],
            "risk_paths": [risk_path.to_dict() for risk_path in self.risk_paths],
            "overall_score": self.overall_score,
            "summary": self.summary,
            "stats": self.stats,
            "scan_trust_level": self.scan_trust_level,
            "policy_decision": self.policy_decision,
            "fatal_errors": self.fatal_errors,
            "correlation_id": self.correlation_id,
        }
