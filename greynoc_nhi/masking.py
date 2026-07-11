"""Secret masking and fingerprint helpers.

These functions never validate or use credentials. They only transform local
strings for safe display and stable deduplication.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from greynoc_nhi.confidence import is_placeholder_value, is_structural_placeholder


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

# Precompiled hot-path probes (looks_like_secret / _mask_high_entropy_match run
# once per candidate value across every parser).
_HAS_ALPHA_RE = re.compile(r"[A-Za-z]")
_HAS_DIGIT_RE = re.compile(r"\d")
_HAS_LOWER_RE = re.compile(r"[a-z]")
_HAS_UPPER_RE = re.compile(r"[A-Z]")
_HAS_WHITESPACE_RE = re.compile(r"\s")
_HAS_SEPARATOR_RE = re.compile(r"[_\-/+=]")
_KNOWN_PREFIX_RE = re.compile(r"^(sk|pk|ghp|gho|xoxb|SG|AKIA|AIza|sk-ant|whsec)_?[A-Za-z0-9_\-]{8,}")
# Lowercase kebab/snake words ("postgresql-credentials", "redis_password_secret")
# are Kubernetes/Helm resource-name references, not secret material.
_LOWERCASE_WORDS_RE = re.compile(r"[a-z]+(?:[-_][a-z]+)+")

# Precompiled redact_inline_secret passes.
_URL_CRED_RE = re.compile(r"(://[^:\s/]+:)([^@\s/]+)(@)")
_AUTH_BEARER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*['\"]?bearer\s+)([A-Za-z0-9_\-.=+/]{8,})")
_BEARER_RE = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9_\-.=+/]{16,})")
# Keyword assignments: allow a bounded identifier prefix/tail around the secret
# keyword (AWS_SECRET_ACCESS_KEY=...) and an optional closing quote before the
# separator ("api_token": "...").
_KEYWORD_ASSIGN_RE = re.compile(
    r"(?i)([A-Za-z0-9_-]{0,32}?"
    r"(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|webhook[_-]?secret|credential)"
    r"s?[A-Za-z0-9_-]{0,32})(['\"]?\s*[:=]\s*)(['\"]?)([^'\"\s,}]+)"
)
# Every _KEYWORD_ASSIGN_RE keyword alternative contains one of these substrings.
_KEYWORD_GATE_HINTS = ("secret", "token", "passw", "key", "credential")

_DATABRICKS_TOKEN_RE = re.compile(r"^dapi[0-9a-f]{32}")


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
    if lowered.startswith(("rk_live_", "sk_live_", "pk_live_", "rk_test_", "sk_test_", "pk_test_")):
        return "payment_key"
    if lowered.startswith(("sk-", "sk_")) or "openai" in lowered:
        return "openai_api_key"
    if lowered.startswith(("ghp_", "gho_", "ghs_", "ghr_", "ghu_", "github_pat_")):
        return "github_token"
    if lowered.startswith("glpat-"):
        return "gitlab_token"
    if lowered.startswith(("xoxb-", "xoxp-", "xoxe-", "xoxa-", "xoxr-", "xapp-")):
        return "slack_token"
    if lowered.startswith("whsec"):
        return "webhook_secret"
    if value.startswith(("AKIA", "ASIA")):
        return "aws_access_key_id"
    if lowered.startswith("aiza"):
        return "google_api_key"
    if lowered.startswith("dop_v1_"):
        return "digitalocean_token"
    if _DATABRICKS_TOKEN_RE.match(lowered):
        return "databricks_token"
    if lowered.startswith("sg."):
        return "sendgrid_key"
    if lowered.startswith("dckr_pat_"):
        return "docker_hub_token"
    if lowered.startswith("ntn_"):
        return "notion_token"
    if lowered.startswith("lin_api_"):
        return "linear_token"
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


def mask_secret(value: str, *, fingerprint_key: bytes | str | None = None, include_fingerprint: bool = True) -> str:
    """Return a display-safe masked representation of a secret-like value."""
    value = str(value).strip()
    if value.startswith("[REDACTED:"):
        return value
    label = _secret_label(value)
    if not include_fingerprint:
        return f"[REDACTED:{label} len={len(value)}]"
    fp = fingerprint_secret(value, key=fingerprint_key)[:8]
    return f"[REDACTED:{label} len={len(value)} fp={fp}]"


def fingerprint_secret(value: str, *, key: bytes | str | None = None, stable: bool = False) -> str:
    """Return a non-reversible fingerprint without storing the original value.

    By default this uses an in-memory random HMAC key. Callers that need
    explicit cross-process stability must pass their own HMAC key. Raw,
    unsalted hashes are never returned for secret values.
    """
    raw = str(value).encode("utf-8")
    if stable and key is None:
        raise ValueError("Stable fingerprints require an HMAC key")
    return hmac.new(_key_bytes(key), raw, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class RedactionContext:
    """Per-scan redaction context for display masks and fingerprints."""

    fingerprint_key: bytes
    stable_key: bytes | None = None

    @classmethod
    def for_scan(cls) -> "RedactionContext":
        return cls(fingerprint_key=secrets.token_bytes(32))

    def mask(self, value: str, *, include_fingerprint: bool = True) -> str:
        return mask_secret(value, fingerprint_key=self.fingerprint_key, include_fingerprint=include_fingerprint)

    def fingerprint(self, value: str, *, stable: bool = False) -> str:
        key = self.stable_key if stable else self.fingerprint_key
        return fingerprint_secret(value, key=key, stable=stable)

    def redact_text(self, text: str, *, include_fingerprint: bool = False) -> str:
        return redact_inline_secret(text, fingerprint_key=self.fingerprint_key, include_fingerprint=include_fingerprint)


def looks_like_secret(value: str) -> bool:
    """Heuristically decide whether a local string resembles a secret."""
    value = str(value).strip()
    if not value or value.startswith("${{") or value.startswith("$"):
        return False
    if is_placeholder_value(value):
        return "GNOC_FAKE_SECRET_DO_NOT_USE" in value
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in value:
        return True
    if len(value) >= 16 and not _HAS_WHITESPACE_RE.search(value) and _HAS_ALPHA_RE.search(value):
        if _HAS_DIGIT_RE.search(value):
            return True
        if _HAS_SEPARATOR_RE.search(value) and not _LOWERCASE_WORDS_RE.fullmatch(value):
            return True
    if _KNOWN_PREFIX_RE.match(value):
        return True
    return False


def _is_structural_nonsecret(value: str) -> bool:
    """Return True only for values that are *structurally* not secrets and are
    therefore safe to leave readable in evidence.

    This is the redaction-path placeholder test. It is deliberately far stricter
    than a credential-shaped placeholder check: it never skips masking because a
    value merely *contains* a placeholder word ("example", "dummy") or ends in
    "_here", since a real high-entropy secret can contain those substrings and
    skipping it would leak the credential. Only env/template references and
    zero-entropy placeholder tokens/phrases (via is_structural_placeholder)
    qualify -- credential-shaped values like Stripe test keys are still masked.
    """
    if value.startswith("$"):
        return True  # $VAR / ${VAR} / ${{ ctx }} env or template references
    return is_structural_placeholder(value)


def _mask_high_entropy_match(match: re.Match[str], fingerprint_key: bytes | str | None, include_fingerprint: bool) -> str:
    value = match.group(1)
    if _is_structural_nonsecret(value) and "GNOC_FAKE_SECRET_DO_NOT_USE" not in value:
        return value
    has_alpha = bool(_HAS_ALPHA_RE.search(value))
    has_digit = bool(_HAS_DIGIT_RE.search(value))
    has_mixed_case = bool(_HAS_LOWER_RE.search(value) and _HAS_UPPER_RE.search(value))
    if has_alpha and (has_digit or has_mixed_case or any(char in value for char in "_+=-")):
        return mask_secret(value, fingerprint_key=fingerprint_key, include_fingerprint=include_fingerprint)
    return value


def _mask_keyword_assignment(match: re.Match[str], fingerprint_key: bytes | str | None, include_fingerprint: bool) -> str:
    value = match.group(4)
    if len(value) < 8 or _is_structural_nonsecret(value):
        # Env/template references, tiny scalars, and whole-string placeholder
        # tokens are not secrets; masking them would garble evidence. A value is
        # NEVER skipped merely for containing a placeholder word -- a real secret
        # can, and skipping it would leak the credential.
        return match.group(0)
    return match.group(1) + match.group(2) + match.group(3) + mask_secret(
        value, fingerprint_key=fingerprint_key, include_fingerprint=include_fingerprint
    )


def redact_inline_secret(text: str, *, fingerprint_key: bytes | str | None = None, include_fingerprint: bool = False) -> str:
    """Mask obvious assignment or URL password values in evidence text."""
    safe = str(text)
    if len(safe) < 7:
        # Shorter strings cannot match any redaction pattern.
        return safe
    lowered = safe.lower()
    if "-----begin" in lowered:
        safe = PRIVATE_KEY_BLOCK_RE.sub("[REDACTED PRIVATE KEY BLOCK]", safe)
    if "://" in safe:
        safe = _URL_CRED_RE.sub(
            lambda m: m.group(1) + mask_secret(m.group(2), fingerprint_key=fingerprint_key, include_fingerprint=include_fingerprint) + m.group(3),
            safe,
        )
    if "bearer" in lowered:
        safe = _AUTH_BEARER_RE.sub(
            lambda m: m.group(1) + mask_secret(m.group(2), fingerprint_key=fingerprint_key, include_fingerprint=include_fingerprint),
            safe,
        )
        safe = _BEARER_RE.sub(
            lambda m: m.group(1) + mask_secret(m.group(2), fingerprint_key=fingerprint_key, include_fingerprint=include_fingerprint),
            safe,
        )
    if any(hint in lowered for hint in _KEYWORD_GATE_HINTS):
        safe = _KEYWORD_ASSIGN_RE.sub(
            lambda m: _mask_keyword_assignment(m, fingerprint_key, include_fingerprint),
            safe,
        )
    if len(safe) >= 32:
        safe = HIGH_ENTROPY_RE.sub(lambda m: _mask_high_entropy_match(m, fingerprint_key, include_fingerprint), safe)
    return safe


def redact_path_text(text: str) -> str:
    """Redact credential-shaped content from scanner-generated path fields.

    File paths come from the filesystem walk, not parser-captured values, so
    the high-entropy and keyword passes are skipped: they corrupt hash-named
    path segments (dist/app.<32-hex>.js) that reports, baselines, and SARIF
    locations rely on. Private-key blocks and URL-embedded credentials are
    still masked as defense-in-depth.
    """
    safe = str(text)
    if "-----begin" in safe.lower():
        safe = PRIVATE_KEY_BLOCK_RE.sub("[REDACTED PRIVATE KEY BLOCK]", safe)
    if "://" in safe:
        safe = _URL_CRED_RE.sub(
            lambda m: m.group(1) + mask_secret(m.group(2), include_fingerprint=False) + m.group(3),
            safe,
        )
    return safe
