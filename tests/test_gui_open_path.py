"""Tests for the cross-platform Open Reports helper."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


def test_open_path_skipped_when_tk_missing() -> None:
    try:
        from greynoc_nhi.gui import open_path_in_file_manager
    except ImportError:
        pytest.skip("Tkinter not available in this environment")
    assert callable(open_path_in_file_manager)


def test_open_path_uses_startfile_on_windows(tmp_path: Path) -> None:
    try:
        from greynoc_nhi import gui
    except ImportError:
        pytest.skip("Tkinter not available in this environment")
    if not sys.platform.startswith("win"):
        pytest.skip("Windows-specific path")
    with mock.patch("os.startfile", create=True) as mocked:
        assert gui.open_path_in_file_manager(tmp_path) is True
        mocked.assert_called_once_with(str(tmp_path))


def test_open_path_uses_xdg_open_on_linux(tmp_path: Path) -> None:
    try:
        from greynoc_nhi import gui
    except ImportError:
        pytest.skip("Tkinter not available in this environment")
    fake_xdg = "/usr/bin/xdg-open"
    with (
        mock.patch.object(gui.sys, "platform", "linux"),
        mock.patch.object(gui.shutil, "which", side_effect=lambda name: fake_xdg if name == "xdg-open" else None),
        mock.patch.object(gui.subprocess, "Popen") as popen,
    ):
        assert gui.open_path_in_file_manager(tmp_path) is True
        popen.assert_called_once_with([fake_xdg, str(tmp_path)])


def test_open_path_falls_back_to_false_when_no_opener(tmp_path: Path) -> None:
    try:
        from greynoc_nhi import gui
    except ImportError:
        pytest.skip("Tkinter not available in this environment")
    with (
        mock.patch.object(gui.sys, "platform", "linux"),
        mock.patch.object(gui.shutil, "which", return_value=None),
    ):
        assert gui.open_path_in_file_manager(tmp_path) is False


def test_open_path_uses_open_on_macos(tmp_path: Path) -> None:
    try:
        from greynoc_nhi import gui
    except ImportError:
        pytest.skip("Tkinter not available in this environment")
    with (
        mock.patch.object(gui.sys, "platform", "darwin"),
        mock.patch.object(gui.shutil, "which", return_value="/usr/bin/open"),
        mock.patch.object(gui.subprocess, "Popen") as popen,
    ):
        assert gui.open_path_in_file_manager(tmp_path) is True
        popen.assert_called_once_with(["/usr/bin/open", str(tmp_path)])
