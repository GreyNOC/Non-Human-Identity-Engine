"""Rule catalog and finding generation."""

from __future__ import annotations

from dataclasses import dataclass

from greynoc_nhi.models import Finding, NonHumanIdentity
from greynoc_nhi.owasp_mapping import map_rule_to_owasp
from greynoc_nhi.scoring import finding_severity
from greynoc_nhi.utils import stable_id, utc_now


@dataclass(frozen=True)
class RuleTemplate:
    rule_id: str
    title: str
    base_score: int
    category: str
    explanation: str
    why_it_matters: str
    remediation: str
    control_hints: list[str]


RULE_CATALOG: dict[str, RuleTemplate] = {
    "nhi_secret_leakage": RuleTemplate("nhi_secret_leakage", "Secret-like value exposed in project files", 70, "secret exposure", "A credential-like value is present in a local project file.", "Secrets in source trees are easy to copy into commits, images, builds, and client handoffs.", "Move the secret to a managed local secret store or deployment secret manager, rotate it, and keep only placeholders in source.", ["secret scanning", "rotation", "commit hygiene"]),
    "nhi_plaintext_env_secret": RuleTemplate("nhi_plaintext_env_secret", "Plaintext environment secret detected", 75, "secret exposure", "An environment-style value appears to contain a secret.", "Plaintext env files often get shared during app handoff or copied into CI/CD and containers.", "Use .env.example placeholders, keep real values outside source control, and rotate any exposed value.", ["env separation", "secret masking"]),
    "nhi_hardcoded_secret": RuleTemplate("nhi_hardcoded_secret", "Hardcoded secret detected", 75, "secret exposure", "A token, password, or API key appears hardcoded in a config or source file.", "Hardcoded credentials are difficult to rotate and are frequently leaked through repos and build artifacts.", "Replace with environment references and rotate the credential.", ["secure config", "rotation"]),
    "nhi_database_url_with_credentials": RuleTemplate("nhi_database_url_with_credentials", "Database URL includes credentials", 80, "data access", "A database connection string appears to include a username and password.", "Database identities can expose customer or production data if copied into logs, images, or reports.", "Rotate the database password and move connection strings into a protected secret store.", ["database least privilege", "secret storage"]),
    "nhi_private_key_detected": RuleTemplate("nhi_private_key_detected", "Private key material detected", 90, "key material", "A private key block or private-key-like value was found.", "Private keys often grant durable access and are hard to scope after exposure.", "Revoke and replace the key pair, then store keys outside the source tree.", ["key rotation", "key custody"]),
    "nhi_cloud_key_detected": RuleTemplate("nhi_cloud_key_detected", "Cloud credential detected", 85, "cloud access", "A cloud credential pattern or cloud client secret was found.", "Cloud credentials can grant broad infrastructure, storage, and customer data access.", "Rotate the credential and replace long-lived keys with workload identity or short-lived credentials where possible.", ["cloud IAM", "short-lived credentials"]),
    "nhi_github_token_detected": RuleTemplate("nhi_github_token_detected", "GitHub token detected", 80, "source control access", "A GitHub token-like value was found.", "Source control tokens can read or write code, packages, workflows, and deployment paths.", "Revoke and rotate the token, then scope any replacement to the minimum required repository and permission.", ["SCM least privilege", "token rotation"]),
    "nhi_ai_provider_key_detected": RuleTemplate("nhi_ai_provider_key_detected", "AI provider API key detected", 70, "AI service access", "An AI provider API key-like value was found.", "AI keys can create unexpected spend and may expose sensitive prompts or tool workflows.", "Rotate the key and move it into a local or deployment secret mechanism.", ["AI key custody", "spend controls"]),
    "nhi_payment_key_detected": RuleTemplate("nhi_payment_key_detected", "Payment provider secret key detected", 90, "payment access", "A payment provider secret-key-like value was found.", "Payment API keys can affect billing, customers, refunds, and financial workflows.", "Revoke the key immediately, rotate webhooks, and scope replacement keys.", ["payment controls", "rotation"]),
    "nhi_webhook_secret_exposed": RuleTemplate("nhi_webhook_secret_exposed", "Webhook URL or secret exposed", 65, "webhook access", "A webhook URL or webhook signing secret was found.", "Webhook URLs can trigger workflows or receive sensitive event data if exposed.", "Rotate the webhook URL/secret and move it out of source files.", ["webhook rotation", "event validation"]),
    "nhi_oauth_client_secret_present": RuleTemplate("nhi_oauth_client_secret_present", "OAuth client secret present", 75, "OAuth access", "An OAuth client secret appears in a project file.", "OAuth client secrets can allow impersonation of an application identity.", "Rotate the client secret and store it in protected runtime configuration.", ["OAuth hygiene", "secret storage"]),
    "nhi_broad_oauth_scope": RuleTemplate("nhi_broad_oauth_scope", "Broad OAuth scopes requested", 70, "OAuth scope", "An OAuth app requests broad scopes.", "Broad scopes increase blast radius if the app secret or refresh token leaks.", "Reduce scopes to the minimum needed and require owner approval for broad scopes.", ["least privilege", "approval gates"]),
    "nhi_overprivileged_nhi": RuleTemplate("nhi_overprivileged_nhi", "Overprivileged non-human identity", 75, "privilege", "A non-human identity appears to have broad or host-level permissions.", "Overprivileged automation turns small leaks into large incidents.", "Reduce permissions, split duties, and remove host-level access unless explicitly required.", ["least privilege", "separation of duties"]),
    "nhi_long_lived_secret": RuleTemplate("nhi_long_lived_secret", "Long-lived secret suspected", 55, "rotation", "The credential appears to lack expiry or age evidence.", "Long-lived credentials stay useful to attackers after accidental exposure.", "Prefer short-lived credentials and document expiry.", ["expiry", "rotation"]),
    "nhi_no_rotation_policy": RuleTemplate("nhi_no_rotation_policy", "No rotation evidence found", 45, "rotation", "No rotation status was found for a secret-bearing identity.", "Without rotation evidence, old credentials can survive staff changes and project handoffs.", "Add rotation ownership, cadence, and last-rotated evidence.", ["rotation policy", "owner review"]),
    "nhi_environment_isolation_failure": RuleTemplate("nhi_environment_isolation_failure", "Production secret or deployment path mixed into local/dev config", 70, "environment isolation", "A production deployment or production secret appears reachable from a general project config.", "Mixing production and development identities makes accidental exposure more likely before release.", "Separate dev/staging/prod credentials and require production deployment gates.", ["environment isolation", "approval gates"]),
    "nhi_nhi_reuse_suspected": RuleTemplate("nhi_nhi_reuse_suspected", "NHI reuse suspected", 45, "identity reuse", "The same identity fingerprint appears in more than one location.", "Reused automation identities make rotation harder and expand blast radius.", "Create separate identities per environment and purpose.", ["identity segmentation", "rotation"]),
    "nhi_human_use_of_nhi_suspected": RuleTemplate("nhi_human_use_of_nhi_suspected", "Human use of NHI suspected", 45, "governance", "The identity lacks clear automation ownership or approval evidence.", "Shared automation credentials can become shadow human access.", "Assign an owner, restrict interactive use, and log usage.", ["ownership", "logging"]),
    "nhi_ci_cd_broad_permissions": RuleTemplate("nhi_ci_cd_broad_permissions", "CI/CD workflow has broad write permission", 70, "CI/CD", "A CI/CD workflow grants write access to sensitive repository capabilities.", "CI/CD tokens can change code, packages, deployments, and releases.", "Set explicit least-privilege permissions per job.", ["CI/CD least privilege"]),
    "nhi_github_actions_write_all": RuleTemplate("nhi_github_actions_write_all", "GitHub Actions permissions set to write-all", 90, "CI/CD", "A workflow grants write-all permissions to the GitHub token.", "write-all gives automation broad repository control and greatly increases CI/CD blast radius.", "Replace write-all with explicit read/write permissions required by each job.", ["GitHub Actions permissions", "least privilege"]),
    "nhi_github_actions_unpinned_action": RuleTemplate("nhi_github_actions_unpinned_action", "Third-party GitHub Action is not pinned to a commit", 55, "third-party NHI", "A workflow uses a third-party action by tag or branch instead of a commit SHA.", "Mutable third-party actions can change behavior without a code review in your repo.", "Pin third-party actions to full commit SHAs and review updates intentionally.", ["supply chain review", "pinning"]),
    "nhi_github_actions_pull_request_target_secrets": RuleTemplate("nhi_github_actions_pull_request_target_secrets", "pull_request_target workflow references secrets", 85, "CI/CD", "A pull_request_target workflow appears to reference secrets.", "This event can expose privileged context around untrusted pull requests if misused.", "Avoid secrets in pull_request_target workflows or add strict checkout and approval gates.", ["CI/CD event hardening"]),
    "nhi_cloud_admin_policy": RuleTemplate("nhi_cloud_admin_policy", "Cloud admin or wildcard policy detected", 90, "cloud access", "A cloud policy appears to grant wildcard or admin-level permissions.", "Wildcard IAM makes a single credential capable of broad infrastructure impact.", "Replace wildcard policies with scoped actions and resources.", ["cloud least privilege"]),
    "nhi_kubernetes_cluster_admin": RuleTemplate("nhi_kubernetes_cluster_admin", "Kubernetes cluster-admin binding detected", 90, "kubernetes", "A Kubernetes identity appears bound to cluster-admin.", "Cluster-admin access can control workloads, secrets, and cluster policy.", "Use namespace-scoped roles and remove cluster-admin from app service accounts.", ["Kubernetes RBAC"]),
    "nhi_kubernetes_automount_token": RuleTemplate("nhi_kubernetes_automount_token", "Service account token automount enabled", 60, "kubernetes", "A workload automounts a service account token.", "Unneeded service account tokens can be stolen from compromised pods.", "Disable automountServiceAccountToken unless the workload requires Kubernetes API access.", ["Kubernetes token hygiene"]),
    "nhi_docker_privileged_container": RuleTemplate("nhi_docker_privileged_container", "Privileged container detected", 80, "container", "A container is configured as privileged.", "Privileged containers greatly expand host and runtime access.", "Remove privileged mode and grant only the exact capabilities needed.", ["container hardening"]),
    "nhi_docker_socket_mount": RuleTemplate("nhi_docker_socket_mount", "Docker socket mounted into container", 85, "container", "A container mounts the Docker socket.", "Docker socket access can be equivalent to host control.", "Remove the socket mount or isolate it behind a narrowly scoped build service.", ["container hardening"]),
    "nhi_browser_extension_risky_permissions": RuleTemplate("nhi_browser_extension_risky_permissions", "Browser extension requests risky permissions", 75, "browser/session access", "A browser extension manifest requests sensitive browser permissions.", "Browser permissions such as cookies, tabs, and all URLs can expose sessions and customer data.", "Remove unnecessary permissions and narrow host permissions.", ["browser least privilege"]),
    "nhi_ai_agent_unapproved_tool_access": RuleTemplate("nhi_ai_agent_unapproved_tool_access", "AI agent tool access lacks approval gate", 80, "AI agent access", "An AI agent can use risky tools without approval.", "Unapproved tool access can turn prompt mistakes into file, email, GitHub, or cloud actions.", "Require approval gates for high-impact tools and separate production tools.", ["AI approval gates"]),
    "nhi_ai_agent_sensitive_data_access": RuleTemplate("nhi_ai_agent_sensitive_data_access", "AI agent has sensitive data access", 70, "AI agent access", "An AI agent config indicates access to sensitive data or memory.", "Sensitive context can persist beyond the immediate task if not governed.", "Disable sensitive memory by default and define retention and redaction rules.", ["AI data minimization"]),
    "nhi_ai_agent_shell_access": RuleTemplate("nhi_ai_agent_shell_access", "AI agent can run shell commands without approval", 90, "AI agent access", "An AI agent has shell-like tool access without an approval gate.", "Shell access can modify files, run deployments, or touch local secrets.", "Require human approval and restrict shell access to trusted workspaces.", ["AI tool governance"]),
    "nhi_mcp_server_high_risk_tool_access": RuleTemplate("nhi_mcp_server_high_risk_tool_access", "MCP server exposes high-risk tools", 80, "MCP access", "An MCP config exposes tools such as shell, database, browser, cloud, email, or GitHub.", "MCP connectors can bridge AI workflows into sensitive systems.", "Use allowlists, scoped tokens, and approval gates for high-risk MCP servers.", ["MCP allowlists"]),
    "nhi_mcp_filesystem_broad_access": RuleTemplate("nhi_mcp_filesystem_broad_access", "MCP filesystem server has broad access", 80, "MCP access", "An MCP filesystem server appears to access broad project or home paths.", "Broad filesystem access can expose source code, secrets, and local customer data.", "Limit filesystem roots to the smallest required directories.", ["filesystem scoping"]),
    "nhi_service_account_key_file": RuleTemplate("nhi_service_account_key_file", "Service account key file detected", 85, "service account", "A service account key file or key resource was detected.", "Exported service account keys are durable credentials that are easy to copy.", "Rotate the key and prefer workload identity or managed federation.", ["workload identity", "key rotation"]),
    "nhi_missing_owner": RuleTemplate("nhi_missing_owner", "Identity has no owner", 30, "governance", "No owner metadata was found for this identity.", "Unowned identities are harder to rotate, approve, and remove during offboarding.", "Assign a named owner or team for the identity.", ["ownership"]),
    "nhi_missing_logging_evidence": RuleTemplate("nhi_missing_logging_evidence", "No logging evidence found", 30, "monitoring", "No logging or audit evidence was found for this identity.", "Without logging, misuse and stale access are harder to detect.", "Enable audit logs or document where usage is monitored.", ["logging", "auditability"]),
    "nhi_secret_sprawl_same_file": RuleTemplate("nhi_secret_sprawl_same_file", "Secret sprawl concentrated in one file", 85, "secret exposure", "Multiple secret-bearing identities were detected in the same file.", "When one file contains many credentials, a single copy, screenshot, attachment, or accidental commit can expose several systems at once.", "Split real secrets out of source files, keep only placeholders, rotate exposed values, and add a pre-commit secret scan.", ["secret minimization", "pre-commit scanning"]),
    "nhi_identity_exposure_chain": RuleTemplate("nhi_identity_exposure_chain", "Identity exposure chain across project surfaces", 75, "blast radius", "The same provider or identity family appears across multiple project surfaces.", "Repeated provider identities across env, CI/CD, containers, and config files create a transitive blast radius that single-file scanning misses.", "Separate identities by environment and surface, then rotate and scope each independently.", ["identity segmentation", "blast-radius reduction"]),
    "nhi_ai_mcp_privilege_bridge": RuleTemplate("nhi_ai_mcp_privilege_bridge", "AI agent and MCP tools form a privilege bridge", 95, "AI/MCP access", "Unapproved AI agent tools coexist with MCP shell, command, or filesystem access.", "This combination can bridge prompt-driven workflows into local code, file, shell, browser, or external-system access without a human approval gate.", "Disable unapproved high-impact tools, scope MCP roots tightly, and require explicit approval before shell, file-write, deploy, email, cloud, or GitHub actions.", ["AI approval gates", "MCP allowlists", "filesystem scoping"]),
    "nhi_untrusted_ci_deploy_path": RuleTemplate("nhi_untrusted_ci_deploy_path", "Untrusted CI/CD deployment path", 95, "CI/CD", "Broad CI/CD permissions, production secrets, and unpinned third-party actions were observed together.", "This is a high-risk deployment chain: mutable third-party code can run in a workflow with write access and production context.", "Pin actions to commit SHAs, remove write-all, isolate deployment secrets, and require protected environment approvals.", ["GitHub Actions hardening", "deployment approval"]),
    "nhi_build_pipeline_secret_sink": RuleTemplate("nhi_build_pipeline_secret_sink", "Build pipeline can sink secrets into privileged runtime surfaces", 90, "build pipeline", "Secret-bearing build or package surfaces coexist with privileged container or host-level access.", "Secrets in build args, package scripts, or compose files can leak into image layers, logs, host mounts, or local developer machines.", "Remove secrets from build-time inputs, use runtime secret injection, and remove Docker socket or privileged container access.", ["build secret hygiene", "container hardening"]),
    "nhi_shadow_admin_path": RuleTemplate("nhi_shadow_admin_path", "Shadow admin automation path detected", 95, "privilege", "Multiple automation surfaces combine into admin-equivalent access.", "CI/CD write access plus Docker socket, privileged containers, cluster-admin, or wildcard cloud policies can create an unplanned administrator path.", "Break the chain: reduce CI/CD token permissions, remove host/container admin access, and scope cloud/Kubernetes identities.", ["least privilege", "admin path review"]),
    "nhi_customer_data_secret_coupling": RuleTemplate("nhi_customer_data_secret_coupling", "Secret-bearing identity is coupled to customer data access", 90, "data access", "A secret-bearing identity appears to have customer-data access.", "A leaked credential with customer-data access is materially worse than an isolated service token because it can expose regulated or client-sensitive records.", "Rotate the secret, reduce data permissions, and separate read/write/data-export roles.", ["data minimization", "database least privilege"]),
    "nhi_orphaned_identity_cluster": RuleTemplate("nhi_orphaned_identity_cluster", "Orphaned identity cluster detected", 70, "governance", "Most discovered identities lack owner and logging evidence.", "A single unowned identity is a cleanup task; a cluster of them means offboarding, rotation, and incident response will be unreliable.", "Assign owners, add logging evidence, and review stale identities as a tracked remediation sprint.", ["ownership", "logging", "offboarding"]),
    "nhi_production_without_approval_gate": RuleTemplate("nhi_production_without_approval_gate", "Production-capable automation lacks approval gates", 90, "environment isolation", "Multiple production-capable identities lack explicit approval gates.", "Production automation without review gates lets mistakes, compromised workflows, or unsafe AI/MCP tool calls reach live systems.", "Require protected environment approvals and human gates for production deploy, shell, cloud, database, and destructive tools.", ["production gates", "change control"]),
    "nhi_secret_file_not_gitignored": RuleTemplate("nhi_secret_file_not_gitignored", "Secret-bearing env file lacks gitignore guard", 65, "repository hygiene", "A secret-bearing .env-style file was found without a root .gitignore guard.", "Even fake-looking env files are often copied into real projects, and missing ignore rules make accidental commits more likely.", "Add .env, .env.*, and local secret files to .gitignore; keep checked-in examples value-free.", ["repo hygiene", "commit prevention"]),
}


def make_finding(rule_id: str, identity: NonHumanIdentity, evidence: list[str] | None = None, score_boost: int = 0) -> Finding:
    template = RULE_CATALOG[rule_id]
    score = min(100, template.base_score + score_boost)
    return Finding(
        id=stable_id("finding", rule_id, identity.id, identity.file_path, identity.line_number, evidence or identity.evidence),
        rule_id=rule_id,
        title=template.title,
        severity=finding_severity(score),
        risk_score=score,
        category=template.category,
        identity_id=identity.id,
        identity_name=identity.name,
        source=identity.source,
        file_path=identity.file_path,
        line_number=identity.line_number,
        explanation=template.explanation,
        why_it_matters=template.why_it_matters,
        evidence=evidence or identity.evidence,
        remediation=template.remediation,
        priority="fix now" if score >= 80 else "next sprint" if score >= 60 else "planned hardening",
        owasp_nhi_refs=map_rule_to_owasp(rule_id),
        control_hints=template.control_hints,
        created_at=utc_now(),
    )


def run_rules(identities: list[NonHumanIdentity]) -> list[Finding]:
    """Generate findings from normalized identities."""
    findings: list[Finding] = []
    seen: set[str] = set()
    fingerprints: dict[str, int] = {}
    for identity in identities:
        if identity.secret_fingerprint:
            fingerprints[identity.secret_fingerprint] = fingerprints.get(identity.secret_fingerprint, 0) + 1
        candidate_rules = [tag for tag in identity.tags if tag in RULE_CATALOG]
        if not candidate_rules and identity.has_secret:
            candidate_rules.append("nhi_secret_leakage")
        for rule_id in candidate_rules:
            boost = 10 if identity.admin_access else 0
            finding = make_finding(rule_id, identity, score_boost=boost)
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
        if identity.has_secret and identity.rotation_status in {None, "unknown", "missing"}:
            for rule_id in ["nhi_no_rotation_policy", "nhi_long_lived_secret"]:
                finding = make_finding(rule_id, identity)
                if finding.id not in seen:
                    findings.append(finding)
                    seen.add(finding.id)
        if identity.owner is None:
            finding = make_finding("nhi_missing_owner", identity)
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
        if identity.logging_enabled is None or identity.logging_enabled is False:
            finding = make_finding("nhi_missing_logging_evidence", identity)
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
    for fingerprint, count in fingerprints.items():
        if count <= 1:
            continue
        for identity in [item for item in identities if item.secret_fingerprint == fingerprint]:
            finding = make_finding("nhi_nhi_reuse_suspected", identity, evidence=["Same masked secret fingerprint appears in multiple files."])
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
    return sorted(findings, key=lambda item: (-item.risk_score, item.rule_id, item.file_path or ""))
