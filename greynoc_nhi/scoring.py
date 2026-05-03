"""Deterministic blast-radius and overall risk scoring."""

from __future__ import annotations

from greynoc_nhi.models import Finding, NonHumanIdentity

SEVERITY_BANDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Clean"),
]


def severity_label(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Clean"


def score_identity(identity: NonHumanIdentity) -> int:
    score = 0
    if identity.has_secret:
        score += 20
    if identity.admin_access or any(p in {"*", "write-all", "cluster-admin"} for p in identity.permissions):
        score += 25
    if identity.production_access:
        score += 15
    if identity.external_access:
        score += 10
    if identity.data_access_level in {"customer", "session", "source-code"}:
        score += 15
    if identity.approval_required is False:
        score += 15
    if identity.owner is None:
        score += 5
    if identity.rotation_status in {None, "unknown", "missing"} and identity.has_secret:
        score += 10
    if identity.logging_enabled is False or identity.logging_enabled is None:
        score += 5
    if any(tag in identity.tags for tag in ["private_key", "service_account_key", "filesystem", "host_access"]):
        score += 15
    if "advanced_correlation" in identity.tags:
        score += 10
    if any(tag in identity.tags for tag in ["privilege_bridge", "deployment_path", "shadow_admin", "secret_coupling"]):
        score += 20
    if "secret_sprawl" in identity.tags:
        score += 10
    return min(100, score)


def finding_severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def calculate_overall_score(identities: list[NonHumanIdentity], findings: list[Finding]) -> int:
    if not identities and not findings:
        return 0
    identity_max = max((score_identity(identity) for identity in identities), default=0)
    finding_max = max((finding.risk_score for finding in findings), default=0)
    finding_pressure = min(30, len(findings) * 3)
    critical_pressure = min(20, sum(1 for f in findings if f.severity == "critical") * 5)
    return min(100, max(identity_max, finding_max) + finding_pressure + critical_pressure)
