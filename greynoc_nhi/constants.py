"""Shared constants for the GreyNOC NHI engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_ROOT / "data"
SAMPLE_PROJECT_DIR = DATA_DIR / "sample_project"
DEFAULT_REPORTS_DIR = DATA_DIR / "reports"
DEFAULT_DB_PATH = Path(tempfile.gettempdir()) / "greynoc_nhi" / "greynoc_nhi.sqlite3"
FIRST_RUN_FLAG_PATH = Path(tempfile.gettempdir()) / "greynoc_nhi" / "gui_first_run_seen"

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".cache",
    "target",
    "vendor",
}

SCAN_FILE_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "manifest.json",
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cursor_mcp.json",
    "agents.yaml",
    "agents.yml",
    "agents.json",
    "crew.py",
    "autogen_config.json",
    "litellm_config.yaml",
    "litellm_config.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "azure-pipelines.yml",
    ".gitlab-ci.yml",
    "cdk.json",
    "cdk.context.json",
    "pulumi.yaml",
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    "dependabot.yml",
    "dependabot.yaml",
}

SCAN_EXTENSIONS = {
    ".env",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rb",
    ".php",
    ".java",
    ".cs",
    ".tf",
    ".bicep",
}

MAX_FILE_BYTES = 2 * 1024 * 1024

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
