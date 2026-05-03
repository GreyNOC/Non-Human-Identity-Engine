"""Small local progress indicators for CLI and GUI surfaces."""

from __future__ import annotations

import itertools
import sys
import threading
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class CliPixelIndicator:
    """Terminal-safe animated pixel cluster written to stderr."""

    _frames = (
        "[# . .] [ . ]",
        "[# # .] [ . ]",
        "[. # #] [# ]",
        "[. . #] [# ]",
        "[. # .] [# ]",
        "[# . #] [ . ]",
    )

    def __init__(self, label: str = "Analyzing") -> None:
        self.label = label
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, final: str = "Done") -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.write(f"{final}\n")
        sys.stderr.flush()

    def _run(self) -> None:
        for frame in itertools.cycle(self._frames):
            if self._stop.is_set():
                break
            sys.stderr.write(f"\r{frame} {self.label}...")
            sys.stderr.flush()
            time.sleep(0.12)


def with_cli_indicator(label: str, work: Callable[[], T]) -> T:
    """Run work while showing the CLI pixel indicator."""
    indicator = CliPixelIndicator(label)
    indicator.start()
    try:
        result = work()
    except Exception:
        indicator.stop("Failed")
        raise
    indicator.stop("Analysis complete")
    return result
