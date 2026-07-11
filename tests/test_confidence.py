"""Tests for placeholder detection and confidence calibration."""

from greynoc_nhi.confidence import (
    PROVIDER_SPECIFIC_RULES,
    infer_confidence,
    is_placeholder_value,
    is_weak_placeholder_value,
    should_suppress_candidate,
)

JWT_IO_DEMO_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_placeholder_conventions_are_recognized():
    assert is_placeholder_value("your-token-here")
    assert is_placeholder_value("your_token")
    assert is_placeholder_value("your_openai_api_key_here")
    assert is_placeholder_value("replace_with_real_key")
    assert is_placeholder_value("REPLACE_WITH_SECRET")
    assert is_placeholder_value("INSERT_API_KEY_HERE")
    assert is_placeholder_value("<YOUR_TOKEN>")
    assert is_placeholder_value("${API_KEY}")
    assert is_placeholder_value("$API_KEY")


def test_here_suffix_without_intent_prefix_is_weak_not_suppressed():
    # A "...-here" value that does not lead with an explicit fill-in marker
    # (your/replace/insert/...) is only a WEAK placeholder: it is still detected
    # (looks_like_secret stays True) but at low confidence. This is the safe
    # direction -- a passphrase-style credential such as "Amber-Falcon-Meadow-
    # Here" must not be silently suppressed.
    assert not is_placeholder_value("MY_TOKEN-here")
    assert is_weak_placeholder_value("MY_TOKEN-here")
    assert not is_placeholder_value("Amber-Falcon-Meadow-Here")


def test_repeated_character_runs_are_placeholders():
    assert is_placeholder_value("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    assert is_placeholder_value("xxxxxxxxxxxxxxxxxxxxxxxx")
    assert is_placeholder_value("0000000000000000")
    assert is_placeholder_value("sk-xxxxxxxxxxxxxxxxxxxxxxxx")


def test_stripe_test_mode_keys_are_placeholders():
    # Fixture values are split so the file blob never contains a contiguous
    # token shape (GitHub push protection scans blobs, not runtime values).
    assert is_placeholder_value("sk_test_" "4eC39HqLyjWDarjtT1zdp7dc")
    assert is_placeholder_value("pk_test_" "TYooMQauvdEDq54NiTphI7jx")


def test_jwt_io_demo_token_is_a_placeholder():
    assert is_placeholder_value(JWT_IO_DEMO_TOKEN)
    assert infer_confidence("nhi_jwt_detected", secret_value=JWT_IO_DEMO_TOKEN) == "low"


def test_real_shaped_values_are_not_placeholders():
    assert not is_placeholder_value("GNOC_FAKE_SECRET_DO_NOT_USE_123456")
    assert not is_placeholder_value("wJalrXUtnFEMI7K7MDENGbPxRfiCY0GNOC")
    # Weak substrings do not suppress digit-heavy token-shaped values.
    assert not is_placeholder_value("kyour_a1b2c3d4e5f6")
    assert not is_placeholder_value("todo9f8a7b6c5d4e3f2a1")


def test_generic_shape_rules_no_longer_default_to_high_confidence():
    for rule_id in ("nhi_jwt_detected", "nhi_bearer_token_detected", "nhi_encoded_registry_auth_detected"):
        assert rule_id not in PROVIDER_SPECIFIC_RULES
        assert infer_confidence(rule_id) == "medium"
    assert infer_confidence("nhi_github_token_detected") == "high"
    assert infer_confidence("nhi_ai_provider_key_detected") == "high"


def test_should_suppress_candidate_keeps_sensitive_context_visible():
    assert should_suppress_candidate("comment", "your-token-here")
    assert not should_suppress_candidate("api_key", "your-token-here")
    assert not should_suppress_candidate("api_key", "GNOC_FAKE_SECRET_DO_NOT_USE_123456")
