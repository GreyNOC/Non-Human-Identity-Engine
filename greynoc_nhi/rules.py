"""Rule catalog and finding generation."""

from __future__ import annotations

from dataclasses import dataclass

from greynoc_nhi.ai_mapping import map_rule_to_ai_risk
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
    "nhi_browser_extension_broad_host_background": RuleTemplate("nhi_browser_extension_broad_host_background", "Browser extension has broad host access and background execution", 80, "browser/session access", "A browser extension requests broad host access and has a background script or service worker.", "Background execution plus broad host permissions can observe or alter sessions across many sites.", "Narrow host permissions, remove background access where possible, and document extension ownership and review cadence.", ["browser least privilege", "extension review"]),
    "nhi_ai_agent_framework_detected": RuleTemplate("nhi_ai_agent_framework_detected", "AI agent framework detected", 45, "AI agent access", "A known AI-agent framework import or configuration was found.", "Agent frameworks can become non-human identities once connected to tools, memory, or credentials.", "Document the agent owner, purpose, allowed tools, logging, and revocation path before production use.", ["AI inventory", "ownership"]),
    "nhi_ai_agent_unapproved_tool_access": RuleTemplate("nhi_ai_agent_unapproved_tool_access", "AI agent tool access lacks approval gate", 80, "AI agent access", "An AI agent can use risky tools without approval.", "Unapproved tool access can turn prompt mistakes into file, email, GitHub, or cloud actions.", "Require approval gates for high-impact tools and separate production tools.", ["AI approval gates"]),
    "nhi_ai_agent_sensitive_data_access": RuleTemplate("nhi_ai_agent_sensitive_data_access", "AI agent has sensitive data access", 70, "AI agent access", "An AI agent config indicates access to sensitive data or memory.", "Sensitive context can persist beyond the immediate task if not governed.", "Disable sensitive memory by default and define retention and redaction rules.", ["AI data minimization"]),
    "nhi_ai_agent_shell_access": RuleTemplate("nhi_ai_agent_shell_access", "AI agent can run shell commands without approval", 90, "AI agent access", "An AI agent has shell-like tool access without an approval gate.", "Shell access can modify files, run deployments, or touch local secrets.", "Require human approval and restrict shell access to trusted workspaces.", ["AI tool governance"]),
    "nhi_ai_agent_filesystem_access": RuleTemplate("nhi_ai_agent_filesystem_access", "AI agent has filesystem tool access", 75, "AI agent access", "An AI agent can read or write local filesystem paths.", "Filesystem tool access can expose source code, local secrets, prompt context, and customer data.", "Disable filesystem tools unless approved, scope roots to the minimum required path, and enable tool-call logging.", ["AI tool governance", "filesystem scoping"]),
    "nhi_ai_agent_github_write_access": RuleTemplate("nhi_ai_agent_github_write_access", "AI agent has GitHub write capability", 90, "AI agent access", "An AI agent appears connected to GitHub write scopes or tokens.", "GitHub write access lets an agent modify code, workflows, packages, or deployment paths.", "Remove write scopes by default, require human approval for repository writes, and use short-lived scoped credentials.", ["AI approval gates", "SCM least privilege"]),
    "nhi_mcp_server_high_risk_tool_access": RuleTemplate("nhi_mcp_server_high_risk_tool_access", "MCP server exposes high-risk tools", 80, "MCP access", "An MCP config exposes tools such as shell, database, browser, cloud, email, or GitHub.", "MCP connectors can bridge AI workflows into sensitive systems.", "Use allowlists, scoped tokens, and approval gates for high-risk MCP servers.", ["MCP allowlists"]),
    "nhi_mcp_filesystem_broad_access": RuleTemplate("nhi_mcp_filesystem_broad_access", "MCP filesystem server has broad access", 80, "MCP access", "An MCP filesystem server appears to access broad project or home paths.", "Broad filesystem access can expose source code, secrets, and local customer data.", "Limit filesystem roots to the smallest required directories.", ["filesystem scoping"]),
    "nhi_tool_connector_high_risk_access": RuleTemplate("nhi_tool_connector_high_risk_access", "Tool connector exposes high-risk capabilities", 70, "tool connector access", "A tool connector grants access to source control, messaging, storage, databases, cloud, or productivity systems.", "Connectors turn automation identities into cross-system actors and need explicit ownership and least privilege.", "Scope connector permissions, assign an owner, document purpose, and enable audit logging.", ["connector least privilege", "logging"]),
    "nhi_model_gateway_detected": RuleTemplate("nhi_model_gateway_detected", "Model gateway configuration detected", 55, "model gateway access", "A LiteLLM, OpenAI-compatible, local model, or model gateway service was found.", "Model gateways centralize AI provider access and can route prompts, credentials, and sensitive data across providers.", "Protect gateway credentials, enable request logging, define data retention, and restrict administrative access.", ["AI gateway governance", "logging"]),
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
    "nhi_ci_deployment_without_approval": RuleTemplate("nhi_ci_deployment_without_approval", "CI/CD deployment identity lacks approval gate", 95, "CI/CD", "A CI/CD identity combines broad token permissions, deployment capability, and no approval evidence.", "A compromised or mistaken pipeline can deploy to production without a human control point.", "Require protected deployment environments, reduce token scopes, and require human approval for production deploys.", ["deployment gates", "CI/CD least privilege"]),
    "nhi_secret_file_not_gitignored": RuleTemplate("nhi_secret_file_not_gitignored", "Secret-bearing env file lacks gitignore guard", 65, "repository hygiene", "A secret-bearing .env-style file was found without a root .gitignore guard.", "Even fake-looking env files are often copied into real projects, and missing ignore rules make accidental commits more likely.", "Add .env, .env.*, and local secret files to .gitignore; keep checked-in examples value-free.", ["repo hygiene", "commit prevention"]),
    "nhi_package_registry_token_detected": RuleTemplate("nhi_package_registry_token_detected", "Package registry token detected", 80, "package registry access", "A package registry authentication token was found.", "Registry tokens can publish, replace, or pull private packages and can be abused in build or dependency supply-chain paths.", "Rotate the token, scope it read-only or publish-only as needed, and store it outside project files.", ["package registry least privilege", "rotation"]),
    "nhi_deployment_platform_token_detected": RuleTemplate("nhi_deployment_platform_token_detected", "Deployment platform token detected", 85, "deployment access", "A deployment platform token was found.", "Deployment tokens can ship code, change environment variables, or access production release settings.", "Rotate the token, scope it to the required project, and require protected deployment approvals.", ["deployment gates", "token scoping"]),
    "nhi_monitoring_dsn_exposed": RuleTemplate("nhi_monitoring_dsn_exposed", "Monitoring DSN exposed", 45, "monitoring", "A monitoring or telemetry DSN was found.", "A DSN is not always a full secret, but it can enable noisy event injection, project discovery, or leakage of telemetry routing details.", "Move DSNs to public-safe config only when intended, restrict ingest settings, and avoid coupling DSNs with private auth tokens.", ["telemetry hygiene"]),
    "nhi_encoded_registry_auth_detected": RuleTemplate("nhi_encoded_registry_auth_detected", "Encoded package registry auth detected", 80, "package registry access", "A package registry auth value was found in a config file.", "Encoded registry auth can still grant package access and often leaks through dotfiles or container build contexts.", "Rotate the registry credential and replace checked-in auth with user-local or CI secret injection.", ["registry auth hygiene", "build context hygiene"]),
    "nhi_bearer_token_detected": RuleTemplate("nhi_bearer_token_detected", "Bearer token hardcoded in HTTP authorization config", 80, "API access", "A Bearer token appears hardcoded in local code or config.", "Bearer tokens are directly replayable credentials if exposed, even though this tool never validates or uses them.", "Rotate the token and load Authorization headers from a protected runtime secret source.", ["HTTP auth hygiene", "rotation"]),
    "nhi_jwt_detected": RuleTemplate("nhi_jwt_detected", "JWT-like token detected", 70, "session or API token", "A JWT-like token appears in project files.", "JWTs can represent service, session, or automation access and may carry sensitive claims even without validation.", "Remove the token from source, rotate/revoke it if real, and keep only documented placeholders.", ["token hygiene", "session safety"]),
    "nhi_webhook_missing_signature_protection": RuleTemplate("nhi_webhook_missing_signature_protection", "Webhook lacks signing or replay protection evidence", 70, "webhook access", "A webhook endpoint or URL was found without nearby signing secret, HMAC, timestamp, or replay protection evidence.", "Unsigned webhooks can be spoofed or replayed into automation workflows.", "Add webhook signature verification, timestamp freshness checks, replay protection, and revocation instructions.", ["webhook signatures", "replay protection"]),
    "nhi_production_ai_key_in_env": RuleTemplate("nhi_production_ai_key_in_env", "Production AI/API key in environment file", 90, "AI service access", "A production AI or API key appears in an environment file.", "Production provider keys can create spend, expose prompt workflows, and grant access to model gateways or data integrations.", "Rotate this token, move it into a secret manager, and replace it with short-lived workload identity where supported.", ["AI key custody", "secret storage"]),
    "nhi_long_lived_unowned_credential": RuleTemplate("nhi_long_lived_unowned_credential", "Long-lived credential has no owner or expiry", 75, "governance", "A credential-bearing identity lacks owner and expiry metadata.", "Long-lived unowned credentials are hard to rotate, revoke, or investigate during incidents.", "Add owner, business purpose, expiry, review date, and revocation instructions; rotate if the owner is unknown.", ["ownership", "expiry", "rotation"]),
    "nhi_shared_target_exposure": RuleTemplate("nhi_shared_target_exposure", "Multiple NHIs touch the same sensitive target", 80, "blast radius", "Multiple non-human identities appear to touch the same repository, cloud, or data target.", "Shared targets increase blast radius because one weak identity can expose or alter assets used by another.", "Separate identities by target and role, reduce shared write access, and review target-level logging.", ["blast-radius reduction", "least privilege"]),
    "nhi_prompt_artifact_prompt_injection": RuleTemplate("nhi_prompt_artifact_prompt_injection", "Prompt artifact contains injection instructions", 80, "AI prompt security", "A prompt, agent instruction, skill, or documentation artifact contains text that attempts to override instructions.", "Indirect prompt injection can hide in files that agents retrieve or summarize, then steer tool use or data disclosure.", "Remove the instruction, treat external content as untrusted context, and add prompt isolation and tool approval gates.", ["prompt isolation", "content provenance", "approval gates"]),
    "nhi_prompt_artifact_system_prompt_leakage": RuleTemplate("nhi_prompt_artifact_system_prompt_leakage", "Prompt artifact requests system prompt disclosure", 85, "AI prompt security", "A prompt artifact asks the model or agent to reveal hidden system or developer instructions.", "System prompt leakage exposes guardrails, internal workflow details, and instructions attackers can use to bypass controls.", "Delete the disclosure request and add output filters that refuse system, developer, and hidden instruction exposure.", ["system prompt protection", "output policy"]),
    "nhi_prompt_artifact_sensitive_disclosure": RuleTemplate("nhi_prompt_artifact_sensitive_disclosure", "Prompt artifact requests secret or environment disclosure", 90, "AI data exposure", "A prompt artifact asks an agent to print environment variables, credentials, or exfiltrate secrets.", "Agents with file, shell, or memory access can turn these instructions into credential exposure.", "Remove the instruction, deny secret-retrieval requests in policy, and require approval before environment or file reads.", ["secret minimization", "tool approval"]),
    "nhi_prompt_artifact_excessive_agency": RuleTemplate("nhi_prompt_artifact_excessive_agency", "Prompt artifact grants excessive tool agency", 85, "AI agent access", "A prompt artifact instructs an agent to call tools, shell, or external systems without asking.", "Excessive autonomy lets prompt content trigger actions that should require human review.", "Require explicit approval for shell, write, send, deploy, database, cloud, and GitHub actions.", ["approval gates", "least privilege"]),
    "nhi_prompt_artifact_hidden_instruction": RuleTemplate("nhi_prompt_artifact_hidden_instruction", "Hidden prompt instruction detected", 75, "AI prompt security", "HTML, Markdown, or comment-hidden instructions were found in prompt-adjacent content.", "Hidden instructions can be invisible to reviewers but still land in retrieved context for an agent.", "Remove hidden instructions and render or ingest external content through a sanitizer that strips hidden text.", ["content sanitization", "RAG hygiene"]),
    "nhi_prompt_contains_secret_or_credential": RuleTemplate("nhi_prompt_contains_secret_or_credential", "Prompt artifact contains credential-like text", 75, "AI data exposure", "A prompt or instruction file appears to contain a credential-like value.", "Prompts are often logged, shared, cached, or sent to model gateways, making embedded credentials high-risk.", "Rotate the value if real and keep credentials out of prompts and documentation.", ["secret scanning", "prompt hygiene"]),
    "nhi_mcp_unpinned_remote_server": RuleTemplate("nhi_mcp_unpinned_remote_server", "MCP server source is remote or unpinned", 80, "MCP supply chain", "An MCP server is launched from a remote package, GitHub URL, or floating source without a strong pin.", "Unpinned MCP servers can change behavior and inherit local tool and secret access.", "Pin packages to exact versions or commits and review updates intentionally.", ["supply chain pinning", "MCP review"]),
    "nhi_mcp_package_install_without_pinning": RuleTemplate("nhi_mcp_package_install_without_pinning", "MCP command installs package without version or hash pinning", 80, "MCP supply chain", "An MCP command uses a package manager without an exact version, commit, or digest pin.", "Package-manager launched servers create hidden execution paths inside agent workflows.", "Pin package versions, use hashes where supported, and prefer reviewed local wrappers.", ["package pinning", "MCP sandboxing"]),
    "nhi_mcp_remote_script_execution": RuleTemplate("nhi_mcp_remote_script_execution", "MCP config executes a remote script", 95, "MCP supply chain", "An MCP server command appears to run a remote script or curl-piped shell.", "Remote script execution can give unreviewed code access to files, environment variables, and tools.", "Replace remote scripts with pinned, reviewed packages and run untrusted MCP configs only in a sandbox.", ["remote script ban", "sandboxing"]),
    "nhi_mcp_writable_local_server_path": RuleTemplate("nhi_mcp_writable_local_server_path", "MCP server launches from writable local path", 80, "MCP supply chain", "An MCP server is launched from a relative, workspace, temp, or user-writable path.", "Writable server paths let local edits or malicious dependencies alter tools exposed to agents.", "Move MCP servers to reviewed immutable paths and restrict write access.", ["path hardening", "MCP review"]),
    "nhi_mcp_env_secret_passthrough": RuleTemplate("nhi_mcp_env_secret_passthrough", "MCP server receives secret-bearing environment variables", 85, "MCP secret exposure", "MCP configuration passes tokens, keys, or secrets into a tool process.", "Tool processes can leak environment secrets through prompts, logs, subprocesses, or network calls.", "Pass only scoped, short-lived secrets and avoid broad environment inheritance.", ["secret minimization", "process isolation"]),
    "nhi_mcp_unsafe_runtime_flag": RuleTemplate("nhi_mcp_unsafe_runtime_flag", "MCP server uses unsafe runtime flags", 85, "MCP runtime safety", "An MCP command includes unsafe, no-sandbox, allow-all, or dangerously named flags.", "Unsafe runtime flags expand the blast radius of agent tool calls and supply-chain compromise.", "Remove unsafe flags and replace them with explicit allowlists.", ["runtime hardening", "allowlists"]),
    "nhi_mcp_toxic_tool_combination": RuleTemplate("nhi_mcp_toxic_tool_combination", "MCP server combines filesystem, execution, and network tools", 95, "MCP toxic flow", "MCP tool configuration combines local file access, command execution, and external network-capable tools.", "This combination can move secrets from local context to external systems through agent-directed tool calls.", "Split tools by trust boundary, disable unused tools, and require approval for execution or outbound actions.", ["tool segmentation", "approval gates"]),
    "nhi_ai_tool_prompt_injection_description": RuleTemplate("nhi_ai_tool_prompt_injection_description", "Tool description contains prompt-injection behavior", 90, "AI tool poisoning", "A tool name or description instructs the model to ignore policy, reveal context, or leak prior messages.", "Agents often trust tool descriptions as instructions, so poisoned descriptions can steer model behavior.", "Review and sanitize tool metadata, and keep third-party tool descriptions outside the trusted instruction channel.", ["tool metadata review", "prompt isolation"]),
    "nhi_ai_tool_shadowing": RuleTemplate("nhi_ai_tool_shadowing", "Potential tool shadowing detected", 75, "AI tool supply chain", "Two or more tools have overlapping or duplicate names, with at least one appearing third-party or remote.", "Tool shadowing can trick agents or operators into choosing a less trusted implementation.", "Rename tools with clear provenance and require allowlists for third-party tools.", ["tool allowlists", "provenance"]),
    "nhi_ai_tool_name_description_mismatch": RuleTemplate("nhi_ai_tool_name_description_mismatch", "Tool name understates risky capability", 80, "AI tool governance", "A harmless-looking tool name has a description that indicates shell, write, deploy, send, or destructive capability.", "Misleading tool metadata makes it harder to reason about what an autonomous agent can do.", "Rename the tool, split dangerous actions, and require explicit approval for sensitive sinks.", ["tool naming", "approval gates"]),
    "nhi_ai_tool_untrusted_remote_source": RuleTemplate("nhi_ai_tool_untrusted_remote_source", "Tool source is remote or third-party", 70, "AI tool supply chain", "A tool definition references a remote URL, marketplace, package, or third-party source.", "Remote tool sources can change outside local code review while retaining agent permissions.", "Pin remote tool versions and document trusted publishers.", ["supply chain review", "tool provenance"]),
    "nhi_ai_tool_sensitive_sink": RuleTemplate("nhi_ai_tool_sensitive_sink", "Tool can write to a sensitive sink", 85, "AI tool governance", "A tool description or permission indicates write, send, deploy, database, cloud, or repository actions.", "Sensitive sinks need approval because a prompt can otherwise become a real-world action.", "Require schema validation, scoped credentials, logging, and human approval for sensitive writes.", ["approval gates", "audit logging"]),
    "nhi_ai_toxic_flow_untrusted_context_to_privileged_tool": RuleTemplate("nhi_ai_toxic_flow_untrusted_context_to_privileged_tool", "Untrusted AI context can reach a privileged tool", 95, "AI toxic flow", "Untrusted context, prompt artifacts, RAG content, or external messages can influence an agent with privileged tools.", "This is the classic prompt-injection action path: untrusted input reaches a model that can execute, write, send, deploy, or query sensitive systems.", "Add context isolation, retrieval provenance, policy checks, and approval gates before privileged tool calls.", ["toxic flow review", "approval gates", "context isolation"]),
    "nhi_rag_untrusted_source_ingestion": RuleTemplate("nhi_rag_untrusted_source_ingestion", "RAG pipeline ingests untrusted external sources", 75, "RAG security", "A RAG flow ingests web, issue, Slack, email, drive, PDF, or other external content.", "External documents can carry indirect prompt injection or poisoned facts into retrieved context.", "Track source provenance, allowlist ingestion sources, and sanitize retrieved content before prompting.", ["RAG provenance", "allowlists"]),
    "nhi_rag_no_access_filter": RuleTemplate("nhi_rag_no_access_filter", "RAG retrieval lacks visible access filters", 80, "RAG authorization", "A RAG/vector configuration was found without tenant, owner, metadata, or document access filters.", "Missing filters can leak documents across users, teams, or tenants.", "Add tenant/user filters and enforce ownership checks at retrieval time.", ["tenant filters", "document ACLs"]),
    "nhi_rag_context_to_tool_bridge": RuleTemplate("nhi_rag_context_to_tool_bridge", "RAG context feeds agent with privileged tools", 90, "RAG-to-tool bridge", "Retrieved documents appear connected to an agent that can use shell, GitHub, email, database, cloud, or deployment tools.", "Poisoned retrieved context can influence privileged actions if it is mixed into tool-using prompts.", "Separate retrieved context from tool instructions and require approval before privileged actions.", ["context isolation", "tool approval"]),
    "nhi_vector_store_cross_tenant_risk": RuleTemplate("nhi_vector_store_cross_tenant_risk", "Vector store may expose cross-tenant data", 85, "RAG authorization", "A vector store appears to be shared or multi-tenant without explicit tenant filtering.", "Embedding stores can leak or retrieve another tenant's content when metadata filters are absent.", "Partition stores by tenant or enforce metadata filters on every query.", ["tenant isolation", "metadata filters"]),
    "nhi_rag_poisoning_surface": RuleTemplate("nhi_rag_poisoning_surface", "RAG knowledge base has poisoning surface", 80, "RAG poisoning", "A writable or externally ingested knowledge base was detected.", "Writable knowledge bases can let attackers plant content that changes future model behavior.", "Restrict writers, review ingestion jobs, and add document provenance checks.", ["ingestion review", "provenance"]),
    "nhi_llm_output_exec_sink": RuleTemplate("nhi_llm_output_exec_sink", "LLM output flows into code execution", 95, "improper output handling", "Model output appears to be passed to eval, exec, or equivalent code execution.", "Executing model output converts a text-generation issue into arbitrary code execution.", "Never execute raw model output; replace with structured schemas and deterministic handlers.", ["output validation", "code execution ban"]),
    "nhi_llm_output_shell_sink": RuleTemplate("nhi_llm_output_shell_sink", "LLM output flows into shell execution", 95, "improper output handling", "Model output appears to build or execute a shell command.", "Prompt injection can become local command execution when model text reaches a shell.", "Use fixed command allowlists and human approval; do not concatenate model output into shell commands.", ["command allowlists", "approval gates"]),
    "nhi_llm_output_sql_sink": RuleTemplate("nhi_llm_output_sql_sink", "LLM output flows into SQL execution", 85, "improper output handling", "Generated SQL appears to be executed without visible validation.", "Model-generated SQL can expose or modify data beyond the user's intent.", "Validate SQL against an allowlist, enforce read-only roles, and require approval for writes.", ["SQL allowlists", "least privilege"]),
    "nhi_llm_output_html_sink": RuleTemplate("nhi_llm_output_html_sink", "LLM output rendered as HTML without sanitization", 80, "improper output handling", "Model output appears to be rendered as HTML or Markdown without a sanitizer.", "Unsafe rendering can turn generated text into script injection or misleading UI.", "Sanitize HTML/Markdown and render untrusted output in safe components.", ["output sanitization", "XSS protection"]),
    "nhi_llm_function_call_without_schema": RuleTemplate("nhi_llm_function_call_without_schema", "LLM tool call lacks visible schema validation", 75, "AI tool governance", "Tool or function-call arguments from the model are accepted without visible schema validation.", "Unvalidated arguments can trigger unexpected tool actions or data access.", "Validate every tool call with a strict schema before execution.", ["schema validation", "tool policy"]),
    "nhi_llm_autonomous_action_without_gate": RuleTemplate("nhi_llm_autonomous_action_without_gate", "Model output can trigger autonomous action without approval", 90, "AI agent access", "Model output appears to trigger merge, deploy, email, ticket, or other actions without a human gate.", "Autonomous actions combine improper output handling with excessive agency.", "Require explicit human approval and audit logging for external or state-changing actions.", ["approval gates", "audit logging"]),
    "nhi_model_trust_remote_code": RuleTemplate("nhi_model_trust_remote_code", "Model load enables trust_remote_code", 90, "model supply chain", "A model load enables trust_remote_code.", "Remote model repositories can execute code at load time when this flag is enabled.", "Disable trust_remote_code unless the model repository is reviewed and pinned to an immutable revision.", ["model provenance", "code execution review"]),
    "nhi_model_unpinned_revision": RuleTemplate("nhi_model_unpinned_revision", "Model pull lacks revision pinning", 70, "model supply chain", "A Hugging Face or model registry pull lacks an explicit revision, commit, or digest pin.", "Unpinned models can drift silently between development, CI, and production.", "Pin model revisions and document model update review.", ["model pinning", "change control"]),
    "nhi_model_pickle_artifact": RuleTemplate("nhi_model_pickle_artifact", "Pickle or raw PyTorch model artifact detected", 75, "model supply chain", "A pickle, .pt, or .pth model artifact was found.", "Pickle-based model artifacts can execute code when loaded and are unsafe from untrusted sources.", "Prefer safe formats, verify provenance, and never load untrusted pickle artifacts.", ["artifact provenance", "safe model formats"]),
    "nhi_model_gateway_unlogged_routing": RuleTemplate("nhi_model_gateway_unlogged_routing", "Model gateway routing lacks logging evidence", 70, "model gateway access", "A model gateway or provider router was detected without logging or audit settings.", "Unlogged routing makes prompt/data exposure and provider fallback behavior hard to investigate.", "Enable request/audit logging with redaction and retention controls.", ["AI gateway logging", "auditability"]),
    "nhi_model_provider_fallback_without_policy": RuleTemplate("nhi_model_provider_fallback_without_policy", "Model provider fallback lacks policy evidence", 75, "model gateway access", "A model gateway appears to fall back across providers without visible policy controls.", "Provider fallback can silently move data to a different model, region, or retention policy.", "Define allowed providers, data classes, and fallback policy per environment.", ["provider policy", "data residency"]),
    "nhi_model_container_unpinned_digest": RuleTemplate("nhi_model_container_unpinned_digest", "Model-serving container image is not digest-pinned", 70, "model supply chain", "A model-serving Docker image is referenced without a sha256 digest.", "Mutable container tags can change model server code or runtime behavior without review.", "Pin model-serving images by digest and review updates.", ["container pinning", "supply chain review"]),
    "nhi_ai_provider_unbounded_consumption": RuleTemplate("nhi_ai_provider_unbounded_consumption", "AI provider key lacks budget or rate-limit evidence", 70, "AI spend control", "An AI provider key or gateway appears without visible rate, budget, timeout, or loop limits.", "Unbounded consumption can create denial-of-wallet risk and runaway agent loops.", "Set budgets, per-request limits, loop caps, timeouts, and alerting for AI provider usage.", ["spend controls", "rate limits"]),
}

SEVERITY_TO_SCORE = {"low": 30, "medium": 55, "high": 75, "critical": 90}


def make_finding(rule_id: str, identity: NonHumanIdentity, evidence: list[str] | None = None, score_boost: int = 0, custom_templates: dict | None = None) -> Finding:
    if rule_id in RULE_CATALOG:
        template = RULE_CATALOG[rule_id]
    elif custom_templates and rule_id in custom_templates:
        custom = custom_templates[rule_id]
        structural = custom.get("type") == "structural"
        template = RuleTemplate(
            rule_id=rule_id,
            title=custom.get("title", rule_id),
            base_score=SEVERITY_TO_SCORE.get(custom.get("severity", "medium"), 55),
            category="custom rule",
            explanation="A custom structural rule matched this identity." if structural else "A custom local rule pack matched a secret-like value.",
            why_it_matters="Custom structural AI/NHI rules let teams encode project-specific risk conditions without changing engine code." if structural else "Custom rules let teams encode project-specific non-human identity risk patterns without using discovered credentials.",
            remediation=custom.get("remediation", "Review and remediate this custom rule match."),
            control_hints=["custom structural rule"] if structural else ["custom rule pack", "rotation"],
        )
    else:
        return None  # type: ignore[return-value]
    score = min(100, template.base_score + score_boost)
    refs = map_rule_to_owasp(rule_id)
    ai_refs = sorted(set(identity.ai_risk_refs + map_rule_to_ai_risk(rule_id)))
    if custom_templates and rule_id in custom_templates and not refs and custom_templates[rule_id].get("type") != "structural":
        refs = ["NHI2:2025"]
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
        owasp_nhi_refs=refs,
        ai_risk_refs=ai_refs,
        control_hints=template.control_hints,
        created_at=utc_now(),
        confidence=identity.confidence,
        related_identities=identity.related_identities,
        baseline_key=None,
    )


def needs_identity_governance_finding(identity: NonHumanIdentity) -> bool:
    """Return True for identities where owner/logging should be called out individually."""
    return (
        identity.admin_access
        or identity.production_access
        or identity.external_access
        or identity.data_access_level in {"customer", "session", "source-code"}
        or bool(identity.permissions)
        or bool(identity.scopes)
        or bool(identity.tools)
        or identity.identity_type in {"ci_runner", "deployment_identity", "service_account", "mcp_server", "ai_agent", "tool_connector", "model_gateway"}
    )


def _custom_structural_match(identity: NonHumanIdentity, when: dict) -> bool:
    def lower_list(values: list[str]) -> list[str]:
        return [str(value).lower() for value in values]

    checks = {
        "identity_type": identity.identity_type,
        "provider": identity.provider,
        "approval_required": identity.approval_required,
        "has_secret": identity.has_secret,
        "admin_access": identity.admin_access,
        "production_access": identity.production_access,
        "external_access": identity.external_access,
        "data_access_level": identity.data_access_level,
    }
    for key, expected in checks.items():
        if key in when and when[key] != expected:
            return False
    contains_checks = {
        "tools_contains_any": lower_list(identity.tools),
        "permissions_contains_any": lower_list(identity.permissions),
        "scopes_contains_any": lower_list(identity.scopes),
        "tags_contains_any": lower_list(identity.tags),
        "data_classes_contains_any": lower_list(identity.data_classes),
    }
    for key, values in contains_checks.items():
        if key not in when:
            continue
        expected_values = [str(item).lower() for item in when.get(key, [])]
        if not any(any(expected in value for value in values) for expected in expected_values):
            return False
    if "identity_name_contains" in when and str(when["identity_name_contains"]).lower() not in identity.name.lower():
        return False
    return True


def run_rules(identities: list[NonHumanIdentity], custom_templates: dict | None = None) -> list[Finding]:
    """Generate findings from normalized identities."""
    findings: list[Finding] = []
    seen: set[str] = set()
    fingerprints: dict[str, int] = {}
    for identity in identities:
        if identity.secret_fingerprint:
            fingerprints[identity.secret_fingerprint] = fingerprints.get(identity.secret_fingerprint, 0) + 1
        candidate_rules = [tag for tag in identity.tags if tag in RULE_CATALOG or (custom_templates and tag in custom_templates)]
        if not candidate_rules and identity.has_secret:
            candidate_rules.append("nhi_secret_leakage")
        for rule_id in candidate_rules:
            boost = 10 if identity.admin_access else 0
            if rule_id == "nhi_broad_oauth_scope" and identity.owner is None:
                boost += 10
            finding = make_finding(rule_id, identity, score_boost=boost, custom_templates=custom_templates)
            if finding is None:
                continue
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
        if custom_templates:
            for rule_id, custom in custom_templates.items():
                if custom.get("type") != "structural" or not _custom_structural_match(identity, custom.get("when", {})):
                    continue
                finding = make_finding(rule_id, identity, custom_templates=custom_templates)
                if finding and finding.id not in seen:
                    findings.append(finding)
                    seen.add(finding.id)
        inferred_rules: list[str] = []
        if identity.identity_type == "ai_agent" and any(tool in {"filesystem", "read_file", "write_file"} for tool in identity.tools):
            inferred_rules.append("nhi_ai_agent_filesystem_access")
        github_terms = set(identity.tools + identity.permissions + identity.scopes)
        if identity.identity_type == "ai_agent" and any("github" in term.lower() for term in github_terms) and any("write" in term.lower() or term.lower() in {"repo", "workflow"} for term in github_terms):
            inferred_rules.append("nhi_ai_agent_github_write_access")
        if identity.identity_type in {"ci_runner", "deployment_identity"} and identity.production_access and identity.approval_required is not True and (identity.admin_access or any("deploy" in permission.lower() or "write-all" in permission.lower() for permission in identity.permissions)):
            inferred_rules.append("nhi_ci_deployment_without_approval")
        if identity.has_secret and identity.owner is None and not identity.expires_at:
            inferred_rules.append("nhi_long_lived_unowned_credential")
        for rule_id in inferred_rules:
            finding = make_finding(rule_id, identity, custom_templates=custom_templates)
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
        if identity.has_secret and identity.rotation_status in {None, "unknown", "missing"}:
            for rule_id in ["nhi_no_rotation_policy", "nhi_long_lived_secret"]:
                finding = make_finding(rule_id, identity, custom_templates=custom_templates)
                if finding.id not in seen:
                    findings.append(finding)
                    seen.add(finding.id)
        if "advanced_correlation" not in identity.tags and needs_identity_governance_finding(identity):
            if identity.owner is None:
                finding = make_finding("nhi_missing_owner", identity, custom_templates=custom_templates)
                if finding.id not in seen:
                    findings.append(finding)
                    seen.add(finding.id)
            if identity.logging_enabled is None or identity.logging_enabled is False:
                finding = make_finding("nhi_missing_logging_evidence", identity, custom_templates=custom_templates)
                if finding.id not in seen:
                    findings.append(finding)
                    seen.add(finding.id)
    for fingerprint, count in fingerprints.items():
        if count <= 1:
            continue
        for identity in [item for item in identities if item.secret_fingerprint == fingerprint]:
            finding = make_finding("nhi_nhi_reuse_suspected", identity, evidence=["Same masked secret fingerprint appears in multiple files."], custom_templates=custom_templates)
            if finding.id not in seen:
                findings.append(finding)
                seen.add(finding.id)
    return sorted(findings, key=lambda item: (-item.risk_score, item.rule_id, item.file_path or ""))
