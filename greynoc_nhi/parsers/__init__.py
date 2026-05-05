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
    kubernetes,
    mcp_configs,
    modern_saas,
    oauth_configs,
    package_json,
    python_requirements,
    terraform,
    webhooks,
)

PARSERS = [
    env_files,
    generic_config,
    github_actions,
    docker,
    terraform,
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
