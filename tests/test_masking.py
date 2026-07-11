import hashlib

import pytest

from greynoc_nhi.engine import _dedupe_identities, normalize_signal
from greynoc_nhi.masking import (
    fingerprint_secret,
    looks_like_secret,
    mask_secret,
    redact_inline_secret,
    redact_path_text,
)


def test_mask_secret_never_returns_full_value():
    secret = "sk_live_GNOC_FAKE_SECRET_DO_NOT_USE_123456"
    masked = mask_secret(secret)
    assert masked != secret
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in masked
    assert "sk_live" not in masked
    assert masked.startswith("[REDACTED:")
    assert "len=" in masked
    assert "fp=" in masked


def test_secret_fingerprint_is_keyed_by_default():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE"
    assert fingerprint_secret(secret, key=b"test") == fingerprint_secret(secret, key=b"test")
    assert fingerprint_secret(secret, key=b"test") != hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert fingerprint_secret(secret, key=b"one") != fingerprint_secret(secret, key=b"two")


def test_stable_secret_fingerprint_requires_hmac_key():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE"
    with pytest.raises(ValueError):
        fingerprint_secret(secret, stable=True)
    assert fingerprint_secret(secret, key=b"local-stable-key", stable=True) == fingerprint_secret(secret, key=b"local-stable-key", stable=True)


def test_inline_evidence_redaction_omits_fingerprint():
    redacted = redact_inline_secret("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_ARTIFACT_LEAK_123456")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in redacted
    assert "fp=" not in redacted


def test_keyword_masking_handles_identifier_tails_and_json_keys():
    # AWS-style names where the keyword is not immediately followed by the separator.
    unspaced = redact_inline_secret("AWS_SECRET_ACCESS_KEY=GNOC_FAKE_SECRET_DO_NOT_USE/K7MDENG/bPxRfiCY")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in unspaced
    assert "K7MDENG" not in unspaced
    spaced = redact_inline_secret("AWS_SECRET_ACCESS_KEY = GNOC_FAKE_SECRET_DO_NOT_USE/K7MDENG/bPxRfiCY")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in spaced
    assert "K7MDENG" not in spaced
    # JSON-quoted key with a value too short for the high-entropy fallback.
    json_line = redact_inline_secret('"api_token": "GNOC_FAKE_SECRET_DO_NOT_USEab"')
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in json_line
    # .npmrc-style _authToken assignment keeps masking.
    npmrc = redact_inline_secret("//registry.npmjs.org/:_authToken=GNOC_FAKE_SECRET_DO_NOT_USE_npm1")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in npmrc


def test_keyword_masking_skips_placeholders_and_references():
    assert redact_inline_secret("token=${API_KEY}") == "token=${API_KEY}"
    assert redact_inline_secret("token=$API_KEY") == "token=$API_KEY"
    assert redact_inline_secret("password=changeme") == "password=changeme"
    assert redact_inline_secret("token_count: 5") == "token_count: 5"
    assert redact_inline_secret("api_key: your-token-here") == "api_key: your-token-here"


def test_bearer_url_and_private_key_passes_still_mask():
    bearer = redact_inline_secret("Authorization: Bearer GNOC_FAKE_SECRET_DO_NOT_USE_abc123")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in bearer
    url = redact_inline_secret("https://svc:GNOC_FAKE_SECRET_DO_NOT_USEx@internal.example/repo")
    assert "GNOC_FAKE_SECRET_DO_NOT_USEx" not in url
    block = redact_inline_secret("-----BEGIN PRIVATE KEY-----\nGNOC_FAKE_KEY_BODY\n-----END PRIVATE KEY-----")
    assert block == "[REDACTED PRIVATE KEY BLOCK]"
    entropy = redact_inline_secret("value GNOC_FAKE_SECRET_DO_NOT_USE_ABC123xyz end")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_ABC123xyz" not in entropy


def test_looks_like_secret_rejects_prose_and_resource_name_references():
    assert not looks_like_secret("please change this value-later")
    assert not looks_like_secret("postgresql-credentials")
    assert not looks_like_secret("my-app-tls-cert-name")
    assert not looks_like_secret("redis_password_secret")
    # Stripe test-mode keys are placeholders, not production secrets. The
    # literal is split so the blob has no contiguous token (push protection).
    assert not looks_like_secret("sk_test_" "4eC39HqLyjWDarjtT1zdp7dc")


def test_looks_like_secret_keeps_real_token_shapes():
    assert looks_like_secret("GNOC_ADMIN_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert looks_like_secret("GNOC_FAKE_SECRET_DO_NOT_USE_123456")
    assert looks_like_secret("wJalrXUtnFEMI7K7MDENGbPxRfiCY0GNOC")


def test_secret_label_covers_modern_provider_prefixes():
    cases = {
        "sk_test_GNOC_FAKE_SECRET_DO_NOT_USE": "payment_key",
        "pk_test_GNOC_FAKE_SECRET_DO_NOT_USE": "payment_key",
        "glpat-GNOC_FAKE_SECRET_DO_NOT_USE": "gitlab_token",
        "ghs_GNOC_FAKE_SECRET_DO_NOT_USE": "github_token",
        "ghr_GNOC_FAKE_SECRET_DO_NOT_USE": "github_token",
        "ghu_GNOC_FAKE_SECRET_DO_NOT_USE": "github_token",
        "xoxe-1-" "GNOC_FAKE_SECRET_DO_NOT_USE": "slack_token",
        "AKIAGNOCFAKEDONOTUSE": "aws_access_key_id",
        "ASIAGNOCFAKEDONOTUSE": "aws_access_key_id",
        "AIzaGNOC_FAKE_SECRET_DO_NOT_USE": "google_api_key",
        "dop_v1_0123456789abcdef0123456789abcdef": "digitalocean_token",
        "dapi" "0123456789abcdef0123456789abcdef": "databricks_token",
        "SG.GNOCFAKE.DONOTUSE": "sendgrid_key",
        "dckr_pat_" "GNOC_FAKE_SECRET_DO_NOT_USE": "docker_hub_token",
        "ntn_GNOC_FAKE_SECRET_DO_NOT_USE": "notion_token",
        "lin_api_GNOC_FAKE_SECRET_DO_NOT_USE": "linear_token",
    }
    for value, label in cases.items():
        masked = mask_secret(value, include_fingerprint=False)
        assert masked.startswith(f"[REDACTED:{label} "), f"{value} labeled {masked}"


def test_normalize_signal_preserves_commit_sha_and_hash_named_paths():
    sha = "3f9a1b2c4d5e6f708192a3b4c5d6e7f8a1b2c3d4"
    identity = normalize_signal(
        {
            "rule_id": "nhi_secret_leakage",
            "file_path": "dist/app.3f9a1b2c4d5e6f708192a3b4c5d6e7f8.js",
            "line_number": 3,
            "name": "chunk",
            "identity_type": "api key",
            "source": "test",
            "evidence": ["x"],
            "commit_sha": sha,
            "commit_short_sha": sha[:7],
        }
    )
    assert identity.file_path == "dist/app.3f9a1b2c4d5e6f708192a3b4c5d6e7f8.js"
    assert identity.commit_sha == sha
    assert identity.commit_short_sha == sha[:7]


def test_normalize_signal_rejects_non_hex_commit_sha():
    identity = normalize_signal(
        {
            "rule_id": "nhi_secret_leakage",
            "file_path": "x",
            "line_number": 1,
            "name": "n",
            "identity_type": "api key",
            "source": "test",
            "evidence": ["x"],
            "commit_sha": "not a sha",
        }
    )
    assert identity.commit_sha is None


def test_redact_path_text_masks_url_credentials_but_keeps_hash_segments():
    assert "GNOC_FAKE_SECRET_DO_NOT_USEx" not in redact_path_text(
        "https://svc:GNOC_FAKE_SECRET_DO_NOT_USEx@internal.example/repo"
    )
    hashed = "vendor/pkg/3f9a1b2c4d5e6f708192a3b4c5d6e7f8/mod.py"
    assert redact_path_text(hashed) == hashed


def test_dedupe_identities_keeps_first_order_and_last_content():
    base = {
        "rule_id": "nhi_secret_leakage",
        "file_path": "x",
        "line_number": 1,
        "name": "n",
        "identity_type": "api key",
        "source": "test",
    }
    first = normalize_signal({**base, "evidence": ["working tree"]})
    second = normalize_signal({**base, "evidence": ["history"]})
    other = normalize_signal({**base, "line_number": 2, "evidence": ["x"]})
    assert first.id == second.id
    deduped = _dedupe_identities([first, other, second])
    assert [identity.id for identity in deduped] == [first.id, other.id]
    assert deduped[0].evidence == second.evidence
