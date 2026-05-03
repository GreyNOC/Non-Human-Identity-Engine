"""Secret masking and fingerprint helpers.

These functions never validate or use credentials. They only transform local
strings for safe display and stable deduplication.
"""

from __future__ import annotations

import hashlib
import re


SECRET_HINT_RE = re.compile(
    r"(secret|token|password|private[_-]?key|api[_-]?key|client[_-]?secret|access[_-]?key|webhook)",
    re.IGNORECASE,
)


def mask_secret(value: str) -> str:
    """Return a display-safe masked representation of a secret-like value."""
    value = str(value).strip()
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}...{value[-4:]}"


def fingerprint_secret(value: str) -> str:
    """Return a stable SHA-256 fingerprint without storing the original value."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def looks_like_secret(value: str) -> bool:
    """Heuristically decide whether a local string resembles a secret."""
    value = str(value).strip()
    if not value or value.startswith("${{") or value.startswith("$"):
        return False
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in value:
        return True
    if len(value) >= 16 and re.search(r"[A-Za-z]", value) and re.search(r"\d|[_\-/+=]", value):
        return True
    if re.match(r"^(sk|pk|ghp|gho|xoxb|SG|AKIA|AIza|sk-ant|whsec)_?[A-Za-z0-9_\-]{8,}", value):
        return True
    return False


def redact_inline_secret(text: str) -> str:
    """Mask obvious assignment or URL password values in evidence text."""
    safe = str(text)
    safe = re.sub(r"(://[^:\s/]+:)([^@\s/]+)(@)", lambda m: m.group(1) + mask_secret(m.group(2)) + m.group(3), safe)
    safe = re.sub(
        r"(?i)(secret|token|password|api[_-]?key|client[_-]?secret|private[_-]?key|webhook[_-]?secret)(\s*[:=]\s*)(['\"]?)([^'\"\s,}]+)",
        lambda m: m.group(1) + m.group(2) + m.group(3) + mask_secret(m.group(4)),
        safe,
    )
    return safe
