"""Parser for GitHub Actions workflow risk signals."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal


def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return "/.github/workflows/" in normalized and path.suffix.lower() in {".yml", ".yaml"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    if re.search(r"permissions\s*:\s*write-all", text, re.I):
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_write_all",
                file_path=path,
                line_number=next((i for i, l in enumerate(text.splitlines(), 1) if "write-all" in l.lower()), None),
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
    for perm in ["contents", "actions", "id-token", "pull-requests", "packages", "deployments"]:
        if re.search(rf"{re.escape(perm)}\s*:\s*write", text, re.I):
            signals.append(
                make_signal(
                    rule_id="nhi_ci_cd_broad_permissions",
                    file_path=path,
                    line_number=next((i for i, l in enumerate(text.splitlines(), 1) if perm in l and "write" in l.lower()), None),
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
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"uses\s*:\s*([^@\s]+/[^@\s]+)@([^\s#]+)", line, re.I)
        if match and not re.fullmatch(r"[a-f0-9]{40}", match.group(2), re.I):
            signals.append(
                make_signal(
                    rule_id="nhi_github_actions_unpinned_action",
                    file_path=path,
                    line_number=number,
                    name=match.group(1),
                    identity_type="third-party SaaS integration",
                    source="github actions",
                    evidence=line.strip(),
                    provider="github",
                    external_access=True,
                    tags=["ci_cd", "third_party", "unpinned"],
                )
            )
    if "pull_request_target" in lower and "secrets." in text:
        signals.append(
            make_signal(
                rule_id="nhi_github_actions_pull_request_target_secrets",
                file_path=path,
                line_number=next((i for i, l in enumerate(text.splitlines(), 1) if "pull_request_target" in l), None),
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
    if "secrets." in text and ("deploy" in lower or "production" in lower):
        signals.append(
            make_signal(
                rule_id="nhi_environment_isolation_failure",
                file_path=path,
                line_number=next((i for i, l in enumerate(text.splitlines(), 1) if "secrets." in l), None),
                name="Production deployment secrets",
                identity_type="deployment token",
                source="github actions",
                evidence="Workflow deploys with production secrets",
                provider="github",
                production_access=True,
                tags=["ci_cd", "production"],
            )
        )
    return signals
