"""Cross-file NHI correlation and blast-radius analysis.

This module does not validate credentials or call external systems. It looks at
local scan outputs as a graph of identities, capabilities, and files, then emits
synthetic NHI signals for higher-order risks that single-file parsers cannot see.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from greynoc_nhi.masking import redact_inline_secret
from greynoc_nhi.models import NonHumanIdentity, RiskPath
from greynoc_nhi.parsers.base import make_signal
from greynoc_nhi.utils import stable_id

PRIVILEGED_SINKS = {
    "shell",
    "terminal",
    "exec",
    "filesystem",
    "write",
    "github",
    "email",
    "database",
    "deployment",
    "deploy",
    "browser",
    "payment",
    "refund",
    "docker",
    "kubernetes",
    "terraform",
    "aws",
    "azure",
    "gcp",
}
UNTRUSTED_CONTEXT_TAGS = {"untrusted_context", "prompt_artifact", "rag", "external_content", "tool_poisoning", "poisoning_surface"}


def _signal(
    *,
    rule_id: str,
    project_path: str,
    name: str,
    evidence: str,
    identity_type: str = "risk correlation",
    permissions: list[str] | None = None,
    scopes: list[str] | None = None,
    tools: list[str] | None = None,
    tags: list[str] | None = None,
    related_identities: list[str] | None = None,
    admin_access: bool = False,
    production_access: bool = False,
    external_access: bool = False,
    data_access_level: str = "unknown",
    approval_required: bool | None = None,
    ai_attack_class: str | None = None,
    attack_chain_stage: str | None = None,
) -> dict[str, Any]:
    return make_signal(
        rule_id=rule_id,
        file_path=project_path,
        line_number=None,
        name=name,
        identity_type=identity_type,
        source="advanced correlation",
        evidence=redact_inline_secret(evidence),
        permissions=permissions or [],
        scopes=scopes or [],
        tools=tools or [],
        tags=[rule_id, "advanced_correlation", *(tags or [])],
        related_identities=related_identities or [],
        admin_access=admin_access,
        production_access=production_access,
        external_access=external_access,
        data_access_level=data_access_level,
        approval_required=approval_required,
        ai_attack_class=ai_attack_class,
        attack_chain_stage=attack_chain_stage,
    )


def _has_any_tag(identity: NonHumanIdentity, tags: set[str]) -> bool:
    return bool(set(identity.tags) & tags)


def _privileged_tools(identity: NonHumanIdentity) -> set[str]:
    terms = {item.lower() for item in [*identity.tools, *identity.permissions, *identity.scopes, *identity.tool_permissions]}
    return {tool for tool in PRIVILEGED_SINKS if any(tool in term for term in terms)}


def derive_risk_paths(identities: list[NonHumanIdentity], scan_raw: dict[str, Any]) -> list[RiskPath]:
    """Build premium-report action paths from normalized identities."""
    project_path = scan_raw["project_path"]
    paths: list[RiskPath] = []
    untrusted_sources = [item for item in identities if _has_any_tag(item, UNTRUSTED_CONTEXT_TAGS) or item.attack_chain_stage == "untrusted input"]
    agents = [
        item
        for item in identities
        if item.identity_type in {"ai_agent", "tool_connector", "mcp_server"}
        and (_privileged_tools(item) or item.admin_access or item.external_access)
    ]
    credentials = [item for item in identities if item.has_secret or item.secret_fingerprint]

    for source in untrusted_sources:
        for agent in agents:
            if source.id == agent.id:
                continue
            sinks = sorted(_privileged_tools(agent)) or (["admin"] if agent.admin_access else ["external"] if agent.external_access else [])
            if not sinks:
                continue
            if agent.approval_required is True and not agent.admin_access:
                continue
            credential = next((item for item in credentials if item.file_path == agent.file_path or item.provider == agent.provider), None)
            sink = sinks[0]
            paths.append(
                RiskPath(
                    id=stable_id("riskpath", project_path, source.id, agent.id, sink, credential.id if credential else ""),
                    source=source.name,
                    agent=agent.name,
                    tool=sink,
                    credential=credential.name if credential else None,
                    sink=sink,
                    trust_boundary="untrusted context to privileged tool",
                    attack_class=source.ai_attack_class or agent.ai_attack_class or "toxic flow",
                    evidence=[
                        f"{source.name} provides untrusted context from {Path(source.file_path or project_path).name}.",
                        f"{agent.name} exposes privileged sink '{sink}' without a required approval gate.",
                    ],
                    related_identities=[source.id, agent.id, *([credential.id] if credential else [])],
                )
            )
            break
        if len(paths) >= 10:
            break

    return paths


def synthesize_advanced_signals(identities: list[NonHumanIdentity], scan_raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return higher-order risk signals discovered across the whole scan."""
    project_path = scan_raw["project_path"]
    signals: list[dict[str, Any]] = []
    by_file: dict[str, list[NonHumanIdentity]] = defaultdict(list)
    for identity in identities:
        by_file[identity.file_path or project_path].append(identity)

    secret_files = {
        file_path: [identity for identity in group if identity.has_secret]
        for file_path, group in by_file.items()
    }
    for file_path, group in secret_files.items():
        if len(group) >= 3:
            signals.append(
                _signal(
                    rule_id="nhi_secret_sprawl_same_file",
                    project_path=file_path,
                    name=f"Secret sprawl in {Path(file_path).name}",
                    evidence=f"{len(group)} secret-bearing identities were detected in the same file: {Path(file_path).name}.",
                    identity_type="automation script credential",
                    production_access=any(item.production_access for item in group),
                    data_access_level="customer" if any(item.data_access_level == "customer" for item in group) else "unknown",
                    tags=["secret_sprawl"],
                )
            )

    providers = Counter(item.provider for item in identities if item.provider)
    multi_surface_providers = [
        provider
        for provider, count in providers.items()
        if count >= 2 and len({item.source for item in identities if item.provider == provider}) >= 2
    ]
    for provider in multi_surface_providers:
        provider_items = [item for item in identities if item.provider == provider]
        signals.append(
            _signal(
                rule_id="nhi_identity_exposure_chain",
                project_path=project_path,
                name=f"{provider} exposure chain",
                identity_type="third-party SaaS integration",
                evidence=(
                    f"{provider} identities appear across {len({item.source for item in provider_items})} surfaces "
                    f"with {sum(1 for item in provider_items if item.has_secret)} secret-bearing entries."
                ),
                external_access=True,
                production_access=any(item.production_access for item in provider_items),
                data_access_level="customer" if any(item.data_access_level == "customer" for item in provider_items) else "unknown",
                tags=["exposure_chain"],
            )
        )

    has_ai_unapproved = any("ai_agent" in item.tags and item.approval_required is False for item in identities)
    ai_tools = sorted({tool for item in identities if "ai_agent" in item.tags for tool in item.tools})
    mcp_tools = sorted({tool for item in identities if "mcp" in item.tags for tool in item.tools})
    if has_ai_unapproved and any(tool in mcp_tools for tool in ["shell", "command", "filesystem"]):
        signals.append(
            _signal(
                rule_id="nhi_ai_mcp_privilege_bridge",
                project_path=project_path,
                name="AI agent to MCP privilege bridge",
                identity_type="AI agent tool connector",
                evidence=f"Unapproved AI tools ({', '.join(ai_tools) or 'unknown'}) coexist with MCP tools ({', '.join(mcp_tools)}).",
                tools=sorted(set(ai_tools + mcp_tools)),
                admin_access=True,
                external_access=True,
                data_access_level="source-code",
                approval_required=False,
                tags=["ai_agent", "mcp", "privilege_bridge"],
            )
        )

    untrusted_sources = [item for item in identities if _has_any_tag(item, UNTRUSTED_CONTEXT_TAGS) or item.attack_chain_stage == "untrusted input"]
    privileged_agents = [
        item
        for item in identities
        if item.identity_type in {"ai_agent", "tool_connector", "mcp_server"}
        and item.approval_required is not True
        and (_privileged_tools(item) or item.admin_access)
    ]
    if untrusted_sources and privileged_agents:
        source = untrusted_sources[0]
        agent = privileged_agents[0]
        tools = sorted(_privileged_tools(agent)) or sorted(agent.tools)
        signals.append(
            _signal(
                rule_id="nhi_ai_toxic_flow_untrusted_context_to_privileged_tool",
                project_path=project_path,
                name="Untrusted AI context to privileged tool",
                identity_type="AI agent tool connector",
                evidence=f"Untrusted context from {Path(source.file_path or project_path).name} can influence {agent.name}, which exposes privileged tools: {', '.join(tools) or 'admin-equivalent'}.",
                tools=tools,
                admin_access=True,
                external_access=agent.external_access,
                data_access_level=agent.data_access_level,
                approval_required=False,
                related_identities=[source.id, agent.id],
                tags=["ai_agent", "toxic_flow", "untrusted_context", "privileged_sink"],
                ai_attack_class="toxic flow",
                attack_chain_stage="prompt/context",
            )
        )

    has_ci_broad = any("ci_cd" in item.tags and (item.admin_access or "write-all" in item.permissions) for item in identities)
    has_deploy_secret = any(item.production_access and ("ci_cd" in item.tags or item.identity_type == "deployment_identity") for item in identities)
    has_unpinned_action = any("third_party" in item.tags and "unpinned" in item.tags for item in identities)
    ci_deploy_without_gate = [
        item
        for item in identities
        if item.production_access
        and ("ci_cd" in item.tags or item.identity_type in {"ci_runner", "deployment_identity"})
        and item.approval_required is not True
        and (item.admin_access or any("deploy" in permission.lower() or "write-all" in permission.lower() for permission in item.permissions))
    ]
    if has_ci_broad and ci_deploy_without_gate:
        signals.append(
            _signal(
                rule_id="nhi_ci_deployment_without_approval",
                project_path=project_path,
                name="CI/CD deployment without approval",
                identity_type="deployment_identity",
                evidence=f"{len(ci_deploy_without_gate)} CI/CD deployment-capable identities combine broad token permission with no approval evidence.",
                permissions=["write-all", "deployment"],
                admin_access=True,
                production_access=True,
                approval_required=False,
                related_identities=[item.id for item in ci_deploy_without_gate],
                tags=["ci_cd", "deployment_path", "approval_gate"],
            )
        )
    if has_ci_broad and has_deploy_secret and has_unpinned_action:
        signals.append(
            _signal(
                rule_id="nhi_untrusted_ci_deploy_path",
                project_path=project_path,
                name="Untrusted CI/CD deployment path",
                identity_type="CI/CD secret",
                evidence="Broad GitHub Actions permissions, production deployment secrets, and unpinned third-party actions were all observed.",
                permissions=["write-all"],
                admin_access=True,
                production_access=True,
                external_access=True,
                tags=["ci_cd", "third_party", "deployment_path"],
            )
        )

    has_build_secret = any(("docker" in item.tags or "package" in item.tags) and (item.has_secret or item.production_access) for item in identities)
    has_docker_host = any("host_access" in item.tags or "privileged" in item.tags for item in identities)
    if has_build_secret and has_docker_host:
        signals.append(
            _signal(
                rule_id="nhi_build_pipeline_secret_sink",
                project_path=project_path,
                name="Build pipeline secret sink",
                identity_type="automation script credential",
                evidence="Secrets or deployment values appear in Docker/package build surfaces that also expose privileged or host-level container access.",
                admin_access=True,
                production_access=True,
                data_access_level="source-code",
                tags=["build_pipeline", "docker"],
            )
        )

    has_docker_socket = any("host_access" in item.tags for item in identities)
    has_k8s_admin = any("cluster-admin" in item.permissions or "admin_policy" in item.tags for item in identities)
    if has_ci_broad and (has_docker_socket or has_k8s_admin):
        signals.append(
            _signal(
                rule_id="nhi_shadow_admin_path",
                project_path=project_path,
                name="Shadow admin automation path",
                identity_type="automation script credential",
                evidence="CI/CD broad permissions coexist with Docker socket, privileged container, Kubernetes cluster-admin, or cloud wildcard policy signals.",
                permissions=["write-all", "admin-equivalent"],
                admin_access=True,
                production_access=True,
                external_access=True,
                tags=["shadow_admin", "ci_cd"],
            )
        )

    for identity in identities:
        if identity.has_secret and identity.data_access_level == "customer":
            signals.append(
                _signal(
                    rule_id="nhi_customer_data_secret_coupling",
                    project_path=identity.file_path or project_path,
                    name=f"Customer data secret coupling: {identity.name}",
                    identity_type=identity.identity_type,
                    evidence=f"Secret-bearing identity {identity.name} is coupled to customer-data access.",
                    external_access=identity.external_access,
                    production_access=identity.production_access,
                    data_access_level="customer",
                    tags=["customer_data", "secret_coupling"],
                )
            )

    ownerless = sum(1 for item in identities if item.owner is None)
    unlogged = sum(1 for item in identities if item.logging_enabled is None or item.logging_enabled is False)
    secret_without_rotation = sum(1 for item in identities if item.has_secret and item.rotation_status in {None, "unknown", "missing"})
    if len(identities) >= 8 and ownerless / len(identities) >= 0.75 and unlogged / len(identities) >= 0.75:
        signals.append(
            _signal(
                rule_id="nhi_orphaned_identity_cluster",
                project_path=project_path,
                name="Orphaned identity cluster",
                identity_type="governance cluster",
                evidence=f"{ownerless} of {len(identities)} identities lack owners; {unlogged} lack logging evidence; {secret_without_rotation} secrets lack rotation evidence.",
                production_access=any(item.production_access for item in identities),
                external_access=any(item.external_access for item in identities),
                data_access_level="customer" if any(item.data_access_level == "customer" for item in identities) else "unknown",
                tags=["governance", "orphaned_cluster"],
            )
        )

    prod_without_gate = [
        item
        for item in identities
        if item.production_access and item.approval_required is not True and (item.admin_access or item.has_secret or item.tools or item.permissions)
    ]
    if len(prod_without_gate) >= 2:
        signals.append(
            _signal(
                rule_id="nhi_production_without_approval_gate",
                project_path=project_path,
                name="Production automation without approval gate",
                identity_type="deployment token",
                evidence=f"{len(prod_without_gate)} production-capable identities lack explicit approval gates.",
                permissions=sorted({permission for item in prod_without_gate for permission in item.permissions}),
                tools=sorted({tool for item in prod_without_gate for tool in item.tools}),
                admin_access=any(item.admin_access for item in prod_without_gate),
                production_access=True,
                external_access=any(item.external_access for item in prod_without_gate),
                approval_required=False,
                tags=["production", "approval_gate"],
            )
        )

    target_groups: dict[str, list[NonHumanIdentity]] = defaultdict(list)
    for identity in identities:
        for target in sorted(set([identity.provider or "", identity.data_access_level if identity.data_access_level != "unknown" else "", *identity.data_classes])):
            if target and target.lower() not in {"unknown", "none"}:
                target_groups[target.lower()].append(identity)
    for target, group in target_groups.items():
        unique_types = {item.identity_type for item in group}
        if len(group) >= 3 and len(unique_types) >= 2 and any(item.admin_access or item.production_access or item.has_secret for item in group):
            signals.append(
                _signal(
                    rule_id="nhi_shared_target_exposure",
                    project_path=project_path,
                    name=f"Shared NHI target: {target}",
                    identity_type="risk correlation",
                    evidence=f"{len(group)} identities across {len(unique_types)} NHI types touch target '{target}'.",
                    admin_access=any(item.admin_access for item in group),
                    production_access=any(item.production_access for item in group),
                    external_access=any(item.external_access for item in group),
                    data_access_level="customer" if any(item.data_access_level == "customer" for item in group) else "unknown",
                    related_identities=[item.id for item in group],
                    tags=["shared_target", "blast_radius"],
                )
            )
            break

    gitignore_path = Path(project_path) / ".gitignore"
    if not gitignore_path.exists() and any(Path(file_path).name.startswith(".env") for file_path in secret_files):
        signals.append(
            _signal(
                rule_id="nhi_secret_file_not_gitignored",
                project_path=project_path,
                name="Secret-bearing env file without gitignore guard",
                identity_type="repository hygiene control",
                evidence="A secret-bearing .env-style file was observed and no .gitignore file was found at the scanned project root.",
                tags=["repo_hygiene", "secret_sprawl"],
            )
        )

    return signals
