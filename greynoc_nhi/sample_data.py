"""Helpers for bundled fake sample data."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.constants import SAMPLE_PROJECT_DIR


def sample_project_path() -> Path:
    """Return the bundled sample project path."""
    return SAMPLE_PROJECT_DIR
