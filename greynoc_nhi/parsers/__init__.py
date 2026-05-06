"""Parser registry."""

from __future__ import annotations

from . import (
    ai_agents,
    browser_extensions,
    cloud_credentials,
    docker,
    env_files,
    generic_config,
    github_actions,
    gitlab_ci,
    kubernetes,
    mcp_configs,
    modern_saas,
    oauth_configs,
    package_json,
    python_requirements,
    terraform,
    terraform_state,
    webhooks,
)

PARSERS = [
    env_files,
    generic_config,
    github_actions,
    gitlab_ci,
    docker,
    terraform,
    terraform_state,
    kubernetes,
    package_json,
    oauth_configs,
    cloud_credentials,
    browser_extensions,
    ai_agents,
    mcp_configs,
    modern_saas,
    webhooks,
    python_requirements,
]
