"""GitLab CI configuration parser.

GitLab pipelines use a different permission model than GitHub Actions, with
keywords like `secrets:` (Vault integration), `id_tokens:` (OIDC),
`services:`, `protected:`, and `$CI_JOB_TOKEN`. The github_actions parser's
checks don't cover these correctly.
"""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

GITLAB_CI_FILES = {".gitlab-ci.yml", ".gitlab-ci.yaml"}

VARIABLE_LINE_RE = re.compile(
    r"^\s*([A-Z][A-Z0-9_]{2,})\s*:\s*(?:['\"]?)([^'\"#\n]+?)(?:['\"]?)\s*$"
)
SECRET_KEY_HINT_RE = re.compile(
    r"(secret|token|password|api[_-]?key|client[_-]?secret|private[_-]?key|webhook|credential)",
    re.IGNORECASE,
)
VARIABLES_BLOCK_RE = re.compile(r"^\s*variables\s*:\s*(#|$)")
SERVICES_BLOCK_RE = re.compile(r"^\s*services\s*:\s*(#|$)")
CI_DEBUG_RE = re.compile(r"^\s*CI_DEBUG_(TRACE|SERVICES)\s*:\s*['\"]?true", re.IGNORECASE)
DIND_INLINE_RE = re.compile(r"^\s*(-\s*)?(services|image)\s*:", re.IGNORECASE)
TRIGGER_LINE_RE = re.compile(r"^\s*trigger\s*:")
ID_TOKENS_LINE_RE = re.compile(r"^\s*id_tokens\s*:")
SECRETS_LINE_RE = re.compile(r"^\s*secrets\s*:")
PROTECTED_FALSE_RE = re.compile(r"^\s*protected\s*:\s*false", re.IGNORECASE)
RULES_RE = re.compile(r"rules\s*:")
DEPLOY_WORD_RE = re.compile(r"deploy|production|release", re.IGNORECASE)


def should_parse(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_FILES


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    protected_signals: list[Signal] = []
    in_variables = False
    variables_indent = 0
    in_services = False
    services_indent = 0
    job_token_line: int | None = None
    id_tokens_line: int | None = None
    id_tokens_block = False
    secrets_line: int | None = None
    deploy_line: int | None = None
    trigger_block = False
    rules_seen = False
    deploy_word_seen = False
    lines = text.splitlines()

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        bare = line.split("#", 1)[0]
        leading = len(bare) - len(bare.lstrip(" "))

        if job_token_line is None and "$CI_JOB_TOKEN" in line:
            job_token_line = number
        if id_tokens_line is None and "id_tokens" in line:
            id_tokens_line = number
        if ID_TOKENS_LINE_RE.match(line):
            id_tokens_block = True
        if secrets_line is None and SECRETS_LINE_RE.match(line):
            secrets_line = number
        if deploy_line is None and "deploy" in line.lower():
            deploy_line = number
        if TRIGGER_LINE_RE.match(line):
            trigger_block = True
        if not rules_seen and RULES_RE.search(line):
            rules_seen = True
        if not deploy_word_seen and DEPLOY_WORD_RE.search(line):
            deploy_word_seen = True

        if VARIABLES_BLOCK_RE.match(line):
            in_variables = True
            variables_indent = leading
            continue
        if in_variables and stripped and leading <= variables_indent and not stripped.startswith("#"):
            in_variables = False

        if SERVICES_BLOCK_RE.match(line):
            in_services = True
            services_indent = leading
            continue
        if in_services and stripped and leading <= services_indent and not stripped.startswith("#"):
            in_services = False

        if in_variables:
            match = VARIABLE_LINE_RE.match(line)
            if match and SECRET_KEY_HINT_RE.search(match.group(1)):
                value = match.group(2).strip()
                if value and not value.startswith("$") and looks_like_secret(value):
                    signals.append(
                        make_signal(
                            rule_id="nhi_gitlab_ci_plaintext_variable",
                            file_path=path,
                            line_number=number,
                            name=match.group(1),
                            identity_type="ci_runner",
                            source="gitlab ci",
                            evidence=stripped,
                            secret_value=value,
                            provider="gitlab",
                            tags=["ci_cd", "gitlab", "plaintext_secret"],
                        )
                    )

        if CI_DEBUG_RE.match(line):
            signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_debug_trace_enabled",
                    file_path=path,
                    line_number=number,
                    name="GitLab CI debug tracing enabled",
                    identity_type="ci_runner",
                    source="gitlab ci",
                    evidence=stripped,
                    provider="gitlab",
                    tags=["ci_cd", "gitlab", "secret_exposure"],
                    confidence="high",
                )
            )

        if "dind" in bare and "docker" in bare and (in_services or DIND_INLINE_RE.match(bare)):
            signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_dind_privileged",
                    file_path=path,
                    line_number=number,
                    name="GitLab CI docker-in-docker service",
                    identity_type="ci_runner",
                    source="gitlab ci",
                    evidence=bare.strip(),
                    provider="gitlab",
                    admin_access=True,
                    tags=["ci_cd", "gitlab", "privileged"],
                )
            )

        if PROTECTED_FALSE_RE.match(line):
            protected_signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_unprotected_environment",
                    file_path=path,
                    line_number=number,
                    name="GitLab unprotected deployment environment",
                    identity_type="deployment_identity",
                    source="gitlab ci",
                    evidence=stripped,
                    provider="gitlab",
                    production_access=True,
                    external_access=True,
                    tags=["ci_cd", "gitlab", "unprotected_environment"],
                )
            )

    if job_token_line is not None and trigger_block:
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_job_token_exposure",
                file_path=path,
                line_number=job_token_line,
                name="$CI_JOB_TOKEN forwarded to triggered pipeline",
                identity_type="ci_runner",
                source="gitlab ci",
                evidence="$CI_JOB_TOKEN referenced inside a trigger context",
                provider="gitlab",
                external_access=True,
                tags=["ci_cd", "gitlab", "token_exposure"],
            )
        )

    if id_tokens_block:
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_oidc_id_token",
                file_path=path,
                line_number=id_tokens_line,
                name="GitLab OIDC id_token",
                identity_type="cloud_workload_identity",
                source="gitlab ci",
                evidence="id_tokens: configured (OIDC federation to cloud)",
                provider="gitlab",
                external_access=True,
                tags=["ci_cd", "gitlab", "oidc"],
                confidence="medium",
            )
        )

    if secrets_line is not None:
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_vault_secrets",
                file_path=path,
                line_number=secrets_line,
                name="GitLab Vault secrets binding",
                identity_type="ci_runner",
                source="gitlab ci",
                evidence="secrets: keyword used (Vault/HCV integration)",
                provider="gitlab",
                tags=["ci_cd", "gitlab", "vault"],
                confidence="medium",
            )
        )

    signals.extend(protected_signals)

    if rules_seen and "$CI_COMMIT_REF_PROTECTED" not in text:
        if deploy_word_seen:
            signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_deployment_without_protected_check",
                    file_path=path,
                    line_number=deploy_line,
                    name="GitLab deployment without protected-branch gate",
                    identity_type="deployment_identity",
                    source="gitlab ci",
                    evidence="deployment job lacks $CI_COMMIT_REF_PROTECTED rule",
                    provider="gitlab",
                    production_access=True,
                    tags=["ci_cd", "gitlab", "missing_gate"],
                    confidence="medium",
                )
            )

    return signals
