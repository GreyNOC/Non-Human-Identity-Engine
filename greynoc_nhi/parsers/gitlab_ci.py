"""GitLab CI configuration parser.

GitLab pipelines use a different permission model than GitHub Actions, with
keywords like `secrets:` (Vault integration), `id_tokens:` (OIDC),
`services:`, `protected:`, and `$CI_JOB_TOKEN`. The github_actions parser's
checks don't cover these correctly.
"""

from __future__ import annotations

__version__ = 1

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


def should_parse(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_FILES


def _line_iter(text: str):
    return enumerate(text.splitlines(), 1)


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    in_variables = False
    variables_indent = 0

    for number, line in _line_iter(text):
        stripped = line.strip()
        bare = line.split("#", 1)[0]
        leading = len(bare) - len(bare.lstrip(" "))

        if re.match(r"^\s*variables\s*:\s*(#|$)", line):
            in_variables = True
            variables_indent = leading
            continue
        if in_variables and stripped and leading <= variables_indent and not stripped.startswith("#"):
            in_variables = False

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


    if "$CI_JOB_TOKEN" in text and re.search(r"^\s*trigger\s*:", text, re.MULTILINE):
        token_line = next((n for n, l in _line_iter(text) if "$CI_JOB_TOKEN" in l), None)
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_job_token_exposure",
                file_path=path,
                line_number=token_line,
                name="$CI_JOB_TOKEN forwarded to triggered pipeline",
                identity_type="ci_runner",
                source="gitlab ci",
                evidence="$CI_JOB_TOKEN referenced inside a trigger context",
                provider="gitlab",
                external_access=True,
                tags=["ci_cd", "gitlab", "token_exposure"],
            )
        )

    if re.search(r"^\s*id_tokens\s*:", text, re.MULTILINE):
        first_line = next((n for n, l in _line_iter(text) if "id_tokens" in l), None)
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_oidc_id_token",
                file_path=path,
                line_number=first_line,
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

    if re.search(r"^\s*secrets\s*:", text, re.MULTILINE):
        first_line = next(
            (n for n, l in _line_iter(text) if re.match(r"^\s*secrets\s*:", l)), None
        )
        signals.append(
            make_signal(
                rule_id="nhi_gitlab_ci_vault_secrets",
                file_path=path,
                line_number=first_line,
                name="GitLab Vault secrets binding",
                identity_type="ci_runner",
                source="gitlab ci",
                evidence="secrets: keyword used (Vault/HCV integration)",
                provider="gitlab",
                tags=["ci_cd", "gitlab", "vault"],
                confidence="medium",
            )
        )

    for number, line in _line_iter(text):
        if re.search(r"^\s*protected\s*:\s*false", line, re.IGNORECASE):
            signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_unprotected_environment",
                    file_path=path,
                    line_number=number,
                    name="GitLab unprotected deployment environment",
                    identity_type="deployment_identity",
                    source="gitlab ci",
                    evidence=line.strip(),
                    provider="gitlab",
                    production_access=True,
                    external_access=True,
                    tags=["ci_cd", "gitlab", "unprotected_environment"],
                )
            )

    if re.search(r"rules\s*:", text) and "$CI_COMMIT_REF_PROTECTED" not in text:
        if re.search(r"deploy|production|release", text, re.IGNORECASE):
            signals.append(
                make_signal(
                    rule_id="nhi_gitlab_ci_deployment_without_protected_check",
                    file_path=path,
                    line_number=next((n for n, l in _line_iter(text) if "deploy" in l.lower()), None),
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
