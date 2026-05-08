"""Secret masking and fingerprint helpers.

These functions never validate or use credentials. They only transform local
strings for safe display and stable deduplication.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from greynoc_nhi.confidence import is_placeholder_value


SECRET_HINT_RE = re.compile(
    r"(secret|token|password|private[_-]?key|api[_-]?key|client[_-]?secret|access[_-]?key|webhook)",
    re.IGNORECASE,
)

PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
HIGH_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9_+=-])([A-Za-z0-9_+=-]{32,})(?![A-Za-z0-9_+=-])")
_PROCESS_FINGERPRINT_KEY = secrets.token_bytes(32)


def _key_bytes(key: bytes | str | None) -> bytes:
    if key is None:
        return _PROCESS_FINGERPRINT_KEY
    if isinstance(key, bytes):
        return key
    return str(key).encode("utf-8")


def _secret_label(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("sk-ant"):
        return "anthropic_api_key"
    if lowered.startswith(("rk_live_", "sk_live_", "pk_live_")):
        return "payment_key"
    if lowered.startswith(("sk-", "sk_")) or "openai" in lowered:
        return "openai_api_key"
    if lowered.startswith(("ghp_", "gho_", "github_pat_")):
        return "github_token"
    if lowered.startswith(("xoxb-", "xoxp-", "xapp-")):
        return "slack_token"
    if lowered.startswith("whsec"):
        return "webhook_secret"
    if "-----begin" in lowered and "private key" in lowered:
        return "private_key"
    if lowered.startswith("eyj"):
        return "jwt"
    if lowered.startswith("hf_"):
        return "huggingface_token"
    if lowered.startswith("npm_"):
        return "package_registry_token"
    if lowered.startswith("pypi-"):
        return "package_registry_token"
    return "secret"


def mask_secret(value: str, *, fingerprint_key: bytes | str | None = None) -> str:
    """Return a display-safe masked representation of a secret-like value."""
    value = str(value).strip()
    if value.startswith("[REDACTED:"):
        return value
    label = _secret_label(value)
    fp = fingerprint_secret(value, key=fingerprint_key)[:8]
    return f"[REDACTED:{label} len={len(value)} fp={fp}]"


def fingerprint_secret(value: str, *, key: bytes | str | None = None, stable: bool = False) -> str:
    """Return a non-reversible fingerprint without storing the original value.

    By default this uses an in-memory random HMAC key. Callers that need
    explicit cross-process stability must opt into stable=True.
    """
    raw = str(value).encode("utf-8")
    if stable:
        return hashlib.sha256(raw).hexdigest()
    return hmac.new(_key_bytes(key), raw, hashlib.sha256).hexdigest()


def looks_like_secret(value: str) -> bool:
    """Heuristically decide whether a local string resembles a secret."""
    value = str(value).strip()
    if not value or value.startswith("${{") or value.startswith("$"):
        return False
    if is_placeholder_value(value):
        return "GNOC_FAKE_SECRET_DO_NOT_USE" in value
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in value:
        return True
    if len(value) >= 16 and re.search(r"[A-Za-z]", value) and re.search(r"\d|[_\-/+=]", value):
        return True
    if re.match(r"^(sk|pk|ghp|gho|xoxb|SG|AKIA|AIza|sk-ant|whsec)_?[A-Za-z0-9_\-]{8,}", value):
        return True
    return False


def _mask_high_entropy_match(match: re.Match[str]) -> str:
    value = match.group(1)
    if is_placeholder_value(value):
        return value
    has_alpha = bool(re.search(r"[A-Za-z]", value))
    has_digit = bool(re.search(r"\d", value))
    has_mixed_case = bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value))
    if has_alpha and (has_digit or has_mixed_case or any(char in value for char in "_+=-")):
        return mask_secret(value)
    return value


def redact_inline_secret(text: str) -> str:
    """Mask obvious assignment or URL password values in evidence text."""
    safe = str(text)
    safe = PRIVATE_KEY_BLOCK_RE.sub("[REDACTED PRIVATE KEY BLOCK]", safe)
    safe = re.sub(r"(://[^:\s/]+:)([^@\s/]+)(@)", lambda m: m.group(1) + mask_secret(m.group(2)) + m.group(3), safe)
    safe = re.sub(
        r"(?i)(authorization\s*[:=]\s*['\"]?bearer\s+)([A-Za-z0-9_\-.=+/]{8,})",
        lambda m: m.group(1) + mask_secret(m.group(2)),
        safe,
    )
    safe = re.sub(
        r"(?i)(\bbearer\s+)([A-Za-z0-9_\-.=+/]{16,})",
        lambda m: m.group(1) + mask_secret(m.group(2)),
        safe,
    )
    safe = re.sub(
        r"(?i)(secret|token|password|api[_-]?key|client[_-]?secret|private[_-]?key|webhook[_-]?secret)(\s*[:=]\s*)(['\"]?)([^'\"\s,}]+)",
        lambda m: m.group(1) + m.group(2) + m.group(3) + mask_secret(m.group(4)),
        safe,
    )
    safe = HIGH_ENTROPY_RE.sub(_mask_high_entropy_match, safe)
    return safe
