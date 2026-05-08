"""Parser registry."""

from __future__ import annotations

from . import (
    ai_code_flows,
    ai_agents,
    browser_extensions,
    cloud_credentials,
    docker,
    env_files,
    generic_config,
    github_actions,
    kubernetes,
    mcp_configs,
    mcp_supply_chain,
    modern_saas,
    oauth_configs,
    package_json,
    prompt_artifacts,
    rag_configs,
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
    prompt_artifacts,
    ai_agents,
    mcp_configs,
    mcp_supply_chain,
    rag_configs,
    ai_code_flows,
    modern_saas,
    webhooks,
    python_requirements,
]
