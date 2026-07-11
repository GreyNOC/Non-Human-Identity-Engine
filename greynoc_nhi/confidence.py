"""Confidence helpers for local-only NHI detections."""

from __future__ import annotations

import re

CONFIDENCE_LEVELS = {"high", "medium", "low"}

HIGH_CONFIDENCE_RULES = {
    "nhi_private_key_detected",
    "nhi_service_account_key_file",
    "nhi_github_actions_write_all",
    "nhi_github_actions_pull_request_target_secrets",
    "nhi_kubernetes_cluster_admin",
    "nhi_docker_socket_mount",
    "nhi_mcp_filesystem_broad_access",
    "nhi_mcp_server_high_risk_tool_access",
    "nhi_ai_mcp_privilege_bridge",
    "nhi_ai_agent_filesystem_access",
    "nhi_ai_agent_github_write_access",
    "nhi_browser_extension_broad_host_background",
    "nhi_ci_deployment_without_approval",
    "nhi_production_ai_key_in_env",
    "nhi_webhook_missing_signature_protection",
    "nhi_shared_target_exposure",
    "nhi_untrusted_ci_deploy_path",
    "nhi_shadow_admin_path",
}

PROVIDER_SPECIFIC_RULES = {
    "nhi_cloud_key_detected",
    "nhi_github_token_detected",
    "nhi_ai_provider_key_detected",
    "nhi_payment_key_detected",
    "nhi_package_registry_token_detected",
    "nhi_deployment_platform_token_detected",
}

PLACEHOLDER_RE = re.compile(
    r"^(?:changeme|change-me|example|example[_-]?key|dummy|fake|test|token|password|secret|your[_-]?api[_-]?key|replace[_-]?me|<[^>]+>|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)$",
    re.IGNORECASE,
)

# Canonical demo secrets that appear verbatim in docs and tutorials (e.g. the
# jwt.io example token signature). Never treat these as live secrets.
KNOWN_DEMO_SECRET_SIGNATURES = frozenset(
    {
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }
)

_REPEATED_RUN_RE = re.compile(r"(.)\1{4,}")
# A low-entropy token made only of alphabetic word-segments joined by . _ -
# (no digits, no random runs). Used with _STRONG_PHRASE_MARKERS to recognize
# placeholder PHRASES like "your-token-here" while never matching a real
# high-entropy credential (which has digits) or a passphrase-style credential
# (e.g. "Correct-Horse-Sample-Staple") that merely embeds a common English word.
_PLACEHOLDER_PHRASE_RE = re.compile(r"[A-Za-z]+(?:[._-][A-Za-z]+)*")
# Words that mark a placeholder no matter where they appear, matched as whole
# `._-`-delimited SEGMENTS (never as substrings). A real credential essentially
# never contains the literal segment "your"/"example"/"placeholder"; this lets
# "sk-your-api-key-here" suppress via its "your" segment while a passphrase like
# "Data-Subsample-Ridge-Cobalt" (segment "subsample", not "sample") does not.
_STRONG_SEGMENT_MARKERS = frozenset(
    {"your", "changeme", "placeholder", "example", "redacted", "goes", "xxx", "todo"}
)
# Ambiguous words that also occur in diceware/passphrase credentials only count
# when they LEAD the value (imperative placeholder phrases: "replace_with_...",
# "insert_api_key_here"); mid-string they stay detectable (low confidence).
_PREFIX_MARKERS = ("replace", "insert", "paste", "enter", "change")
_SEGMENT_SPLIT_RE = re.compile(r"[._-]+")

_WEAK_WORDS = [
    "changeme",
    "change-me",
    "replace_me",
    "replace-me",
    "replace_with",
    "replace-with",
    "your-api-key",
    "example",
    "dummy",
]
# Broader placeholder conventions; only honored for low-digit values so real
# tokens that merely contain one of these substrings still count as secrets.
_EXTRA_WEAK_WORDS = [
    "placeholder",
    "sample",
    "your_",
    "your-",
    "_here",
    "-here",
    "insert_",
    "insert-",
    "redacted",
    "todo",
]


def normalize_confidence(value: str | None) -> str:
    if value and value.lower() in CONFIDENCE_LEVELS:
        return value.lower()
    return "medium"


def _is_placeholder_phrase(text: str) -> bool:
    """True for a low-entropy alphabetic word-phrase carrying an explicit
    fill-in marker (your-token-here, replace_with_real_key, INSERT_API_KEY_HERE).

    Two gates, both required, keep real credentials out:
    1. the whole value is pure alphabetic segments joined by . _ - (no digits,
       no random runs), so tokens like ghp_Zk84hJq2..._here fail immediately;
    2. it contains a STRONG placeholder-intent marker ("your"/"replace"/...),
       not merely a common word -- so a passphrase like "Correct-Horse-Sample-
       Staple" or "Amber-Falcon-Meadow-Here" is NOT suppressed here (those are
       downgraded to low confidence via is_weak_placeholder_value instead).
    """
    if not _PLACEHOLDER_PHRASE_RE.fullmatch(text):
        return False
    lowered = text.lower()
    if _STRONG_SEGMENT_MARKERS.intersection(_SEGMENT_SPLIT_RE.split(lowered)):
        return True
    # Ambiguous markers only count as a leading imperative, so a passphrase that
    # merely contains one mid-string ("Vivid-Rhubarb-Insert-Cobalt") stays
    # detectable.
    return lowered.startswith(_PREFIX_MARKERS)


def is_structural_placeholder(value: object) -> bool:
    """Values that carry NO credential material and are safe to leave readable
    in redacted evidence: empty strings, env/template references, whole-string
    placeholder tokens, low-entropy placeholder phrases, and all-same-character
    runs. Excludes credential-shaped values (e.g. Stripe test keys), which are
    placeholders for *detection* but must still be masked in evidence.
    """
    text = str(value).strip().strip("'\"")
    if not text:
        return True
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    if text.startswith("${{") and text.endswith("}}"):
        return True
    lowered = text.lower()
    if "localhost" in lowered and not any(marker in text for marker in ["@", "://"]):
        return True
    if PLACEHOLDER_RE.match(text):
        return True
    if _is_placeholder_phrase(text):
        return True
    if _REPEATED_RUN_RE.search(text) and len(set(lowered.replace("-", ""))) <= 3:
        # All-same-character runs (xxxx..., 0000...) and xxxx-xxxx UUID shapes.
        return True
    return False


def is_placeholder_value(value: object) -> bool:
    """Strong placeholder test used to SUPPRESS detection.

    Structural placeholders (is_structural_placeholder) plus canonical
    non-production credential formats: Stripe test-mode keys and known demo
    signatures. A real high-entropy secret that merely *contains* a word like
    "example"/"dummy" or ends in "_here" is NOT suppressed here -- suppressing it
    would drop a live credential. Those weaker signals live in
    is_weak_placeholder_value and only lower confidence.
    """
    text = str(value).strip().strip("'\"")
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    if is_structural_placeholder(value):
        return True
    lowered = text.lower()
    if lowered.startswith(("sk_test_", "pk_test_")):
        # Stripe test-mode keys cannot touch live data or money.
        return True
    return any(signature in text for signature in KNOWN_DEMO_SECRET_SIGNATURES)


def is_weak_placeholder_value(value: object) -> bool:
    """Weaker placeholder conventions used only to LOWER confidence, never to
    suppress detection. A real secret is still captured and reported (at low
    confidence) even if it matches one of these; that is the safe direction for
    a secret scanner where a missed live credential is worse than an extra
    low-confidence finding on a placeholder-shaped string.
    """
    if is_placeholder_value(value):
        return True
    text = str(value).strip().strip("'\"")
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    lowered = text.lower()
    if lowered.endswith(("_here", "-here")):
        return True
    if any(word in lowered for word in _WEAK_WORDS):
        return True
    if sum(char.isdigit() for char in text) < 4 and any(word in lowered for word in _EXTRA_WEAK_WORDS):
        return True
    return False


def should_suppress_candidate(name: str | None, value: object) -> bool:
    text = str(value).strip()
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    if not is_placeholder_value(text):
        return False
    key = (name or "").lower()
    sensitive_context = any(token in key for token in ["secret", "token", "password", "api", "key", "client"])
    return not sensitive_context


def infer_confidence(rule_id: str, evidence: str = "", secret_value: object | None = None, explicit: str | None = None) -> str:
    if explicit:
        return normalize_confidence(explicit)
    if secret_value is not None and is_weak_placeholder_value(secret_value):
        return "low"
    if rule_id in HIGH_CONFIDENCE_RULES or rule_id in PROVIDER_SPECIFIC_RULES:
        return "high"
    if "private key block" in evidence.lower() or "cluster-admin" in evidence.lower() or "docker.sock" in evidence.lower():
        return "high"
    if rule_id in {"nhi_hardcoded_secret", "nhi_secret_leakage", "nhi_monitoring_dsn_exposed"}:
        return "medium"
    return "medium"
