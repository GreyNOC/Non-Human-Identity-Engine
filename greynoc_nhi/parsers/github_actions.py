"""Parser for GitHub Actions workflow risk signals."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset

# CircleCI/Azure/Bitbucket pipelines are handled by iac_extra with
# syntax-correct rules; only GitHub-syntax-compatible names stay here.
CI_FILE_NAMES = {".gitlab-ci.yml", ".gitlab-ci.yaml", "ci_pipeline.yml", "pipeline.yml"}

PERMISSION_NAMES = ("contents", "actions", "id-token", "pull-requests", "packages", "deployments")

WRITE_ALL_RE = re.compile(r"permissions\s*:\s*write-all", re.I)
PERMS_WRITE_BLOCK_RE = re.compile(
    r"(?im)^\s*(contents|actions|id-token|pull-requests|packages|deployments)\s*:\s*write\b"
)
PERMS_FLOW_BLOCK_RE = re.compile(r"(?i)permissions\s*:\s*\{([^}\n]*)\}")
PERM_WRITE_INLINE_RE = re.compile(
    r"(?i)\b(contents|actions|id-token|pull-requests|packages|deployments)\s*:\s*write\b"
)
USES_RE = re.compile(r"uses\s*:\s*([^@\s]+/[^@\s]+)@([^\s#]+)", re.I)
PINNED_COMMIT_RE = re.compile(r"[a-f0-9]{40}", re.I)
PINNED_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}", re.I)
RUN_LINE_RE = re.compile(r"^\s*(?:-\s+)?run\s*:")
INJECTION_RE = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|head_commit|commits)[\w.\[\]]*"
    r"|github\.head_ref"
    r"|(?:github\.event\.)?inputs\.[\w-]+)\s*\}\}"
)
PRT_CHECKOUT_RE = re.compile(r"ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head|head_ref)")
SELF_HOSTED_RE = re.compile(r"runs-on\s*:\s*\[?[^\n]*self-hosted", re.I)
SECRETS_INHERIT_RE = re.compile(r"^\s*secrets\s*:\s*inherit\b", re.M)
DEPLOY_TOKEN_RE = re.compile(
    r"(deploy|deployment|production).*token|token.*(deploy|deployment|production)|secrets\.[A-Z0-9_]*DEPLOY",
    re.I,
)
DEPLOY_SECRET_RE = re.compile(r"secrets\.[A-Z0-9_]*(DEPLOY|PROD)")
DEPLOY_SECRET_HIGH_RE = re.compile(r"secrets\.[A-Z0-9_]*DEPLOY")

def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return ("/.github/workflows/" in normalized or path.name.lower() in CI_FILE_NAMES) and path.suffix.lower() in {".yml", ".yaml"}

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    lines = text.splitlines()
    write_all_match = WRITE_ALL_RE.search(text)
    if write_all_match:
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_write_all",
                file_path=path,
                line_number=line_number_at_offset(text, write_all_match.start()),
                name="GitHub Actions workflow token",
                identity_type="CI/CD secret",
                source="github actions",
                evidence="permissions: write-all",
                permissions=["write-all"],
                provider="github",
                admin_access=True,
                external_access=True,
                tags=["ci_cd", "broad_permissions"],
            )
        )
    perm_offsets: dict[str, int] = {}
    for match in PERMS_WRITE_BLOCK_RE.finditer(text):
        perm_offsets.setdefault(match.group(1).lower(), match.start(1))
    for block in PERMS_FLOW_BLOCK_RE.finditer(text):
        for match in PERM_WRITE_INLINE_RE.finditer(block.group(1)):
            perm_offsets.setdefault(match.group(1).lower(), block.start(1) + match.start(1))
    for perm in PERMISSION_NAMES:
        if perm not in perm_offsets:
            continue
        signals.append(
            make_signal(
                rule_id="nhi_ci_cd_broad_permissions",
                file_path=path,
                line_number=line_number_at_offset(text, perm_offsets[perm]),
                name=f"GitHub Actions {perm} permission",
                identity_type="CI/CD secret",
                source="github actions",
                evidence=f"{perm}: write",
                permissions=[f"{perm}:write"],
                provider="github",
                external_access=True,
                tags=["ci_cd", "broad_permissions"],
            )
        )
    run_indent: int | None = None
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        in_run_context = False
        if RUN_LINE_RE.match(line):
            # Anchor on the `run` token (not the `- ` list marker) so sibling
            # keys like env:/with: at the same depth end the run context.
            run_indent = len(line) - len(line.lstrip(" ").lstrip("- "))
            in_run_context = True
        elif run_indent is not None:
            if indent <= run_indent:
                run_indent = None
            else:
                in_run_context = True
        if in_run_context:
            injection_match = INJECTION_RE.search(line)
            if injection_match:
                signals.append(
                    make_signal(
                        rule_id="nhi_github_actions_expression_injection",
                        file_path=path,
                        line_number=number,
                        name="Untrusted expression in run step",
                        identity_type="CI/CD secret",
                        source="github actions",
                        evidence=stripped,
                        provider="github",
                        external_access=True,
                        tags=["ci_cd", "expression_injection"],
                        confidence="medium",
                    )
                )
        match = USES_RE.search(line)
        if match and not PINNED_COMMIT_RE.fullmatch(match.group(2)) and not PINNED_DIGEST_RE.fullmatch(match.group(2)):
            action = match.group(1)
            first_party = action.lower().startswith(("actions/", "github/"))
            signals.append(
                make_signal(
                    rule_id="nhi_github_actions_unpinned_action",
                    file_path=path,
                    line_number=number,
                    name=action,
                    identity_type="third-party SaaS integration",
                    source="github actions",
                    evidence=stripped,
                    provider="github",
                    external_access=True,
                    tags=["ci_cd", "third_party", "unpinned"] + (["first_party"] if first_party else []),
                    confidence="low" if first_party else None,
                )
            )
    if "pull_request_target" in lower and "secrets." in text:
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_pull_request_target_secrets",
                file_path=path,
                line_number=next((i for i, ln in enumerate(lines, 1) if "pull_request_target" in ln), None),
                name="pull_request_target secret exposure",
                identity_type="CI/CD secret",
                source="github actions",
                evidence="pull_request_target workflow references secrets",
                provider="github",
                production_access="production" in lower or "deploy" in lower,
                external_access=True,
                tags=["ci_cd", "secret_exposure"],
            )
        )
    if "pull_request_target" in lower:
        prt_checkout_match = PRT_CHECKOUT_RE.search(text)
        if prt_checkout_match:
            signals.append(
                make_signal(
                    rule_id="nhi_github_actions_prt_untrusted_checkout",
                    file_path=path,
                    line_number=line_number_at_offset(text, prt_checkout_match.start()),
                    name="pull_request_target checks out PR head",
                    identity_type="CI/CD secret",
                    source="github actions",
                    evidence="pull_request_target workflow checks out untrusted PR head ref",
                    provider="github",
                    external_access=True,
                    tags=["ci_cd", "untrusted_checkout"],
                    confidence="high",
                )
            )
    self_hosted_match = SELF_HOSTED_RE.search(text)
    if self_hosted_match:
        pr_triggered = "pull_request" in lower
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_self_hosted_runner",
                file_path=path,
                line_number=line_number_at_offset(text, self_hosted_match.start()),
                name="Self-hosted GitHub Actions runner",
                identity_type="ci_runner",
                source="github actions",
                evidence=self_hosted_match.group(0).strip() + (" (workflow has pull_request trigger)" if pr_triggered else ""),
                provider="github",
                external_access=pr_triggered,
                tags=["ci_cd", "self_hosted_runner"],
                confidence="medium",
            )
        )
    inherit_match = SECRETS_INHERIT_RE.search(text)
    if inherit_match:
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_secrets_inherit",
                file_path=path,
                line_number=line_number_at_offset(text, inherit_match.start()),
                name="Reusable workflow inherits all secrets",
                identity_type="CI/CD secret",
                source="github actions",
                evidence="secrets: inherit passes every repository secret to the called workflow",
                provider="github",
                tags=["ci_cd", "secret_exposure"],
                confidence="medium",
            )
        )
    if "secrets." in text and ("deploy" in lower or "production" in lower):
        signals.append(
            make_signal(
                rule_id="nhi_environment_isolation_failure",
                file_path=path,
                line_number=next((i for i, ln in enumerate(lines, 1) if "secrets." in ln), None),
                name="Production deployment secrets",
                identity_type="deployment token",
                source="github actions",
                evidence="Workflow deploys with production secrets",
                provider="github",
                production_access=True,
                permissions=["deployment"],
                approval_required="environment:" in lower and "review" in lower,
                tags=["ci_cd", "production"],
            )
        )
    deploy_match = DEPLOY_TOKEN_RE.search(text)
    if deploy_match and ("secrets." in text or DEPLOY_SECRET_RE.search(text)):
        has_approval_gate = any(token in lower for token in ["environment:", "reviewers:", "manual", "approval", "when: manual"])
        if not has_approval_gate:
            signals.append(
                make_signal(
                    rule_id="nhi_ci_deployment_without_approval",
                    file_path=path,
                    line_number=line_number_at_offset(text, deploy_match.start()),
                    name="CI/CD deployment identity",
                    identity_type="deployment_identity",
                    source="ci pipeline",
                    evidence="CI/CD deployment token or production deployment path detected",
                    provider="github" if "/.github/workflows/" in str(path).replace("\\", "/").lower() else "ci/cd",
                    permissions=["deployment"],
                    production_access=True,
                    external_access=True,
                    approval_required=False,
                    tags=["ci_cd", "deployment_path"],
                    confidence="high" if DEPLOY_SECRET_HIGH_RE.search(text) else "medium",
                )
            )
    return signals
