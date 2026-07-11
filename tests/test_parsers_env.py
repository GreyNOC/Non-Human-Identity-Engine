from pathlib import Path

from greynoc_nhi.parsers import env_files


def test_env_parser_detects_openai_key():
    signals = env_files.parse(Path(".env.example"), "OPENAI_API_KEY=FAKE_OPENAI_KEY_DO_NOT_USE_123456\n")
    assert any(s["rule_id"] == "nhi_ai_provider_key_detected" for s in signals)
    assert "FAKE_OPENAI_KEY_DO_NOT_USE" not in signals[0]["evidence"][0]


def test_env_parser_detects_database_url_credentials():
    signals = env_files.parse(Path(".env.example"), "DATABASE_URL=postgres://user:GNOC_FAKE_SECRET_DO_NOT_USE@host/db\n")
    assert any(s["rule_id"] == "nhi_database_url_with_credentials" for s in signals)
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in signals[0]["evidence"][0]


def test_env_parser_handles_export_prefix():
    signals = env_files.parse(Path(".envrc"), "export OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456\n")
    assert any(s["rule_id"] == "nhi_ai_provider_key_detected" and s["name"] == "OPENAI_API_KEY" for s in signals)


def test_env_parser_strips_unquoted_inline_comment():
    signals = env_files.parse(Path(".env"), "API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456 # rotate quarterly\n")
    assert signals[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_123456"


def test_env_parser_new_named_keys():
    text = (
        "AWS_SESSION_TOKEN=GNOC_FAKE_SECRET_DO_NOT_USE_STS_123456\n"
        "DEEPSEEK_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DS_123456\n"
        "SECRET_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DJANGO_123456\n"
    )
    signals = env_files.parse(Path(".env"), text)
    rules = {s["name"]: s["rule_id"] for s in signals}
    assert rules["AWS_SESSION_TOKEN"] == "nhi_cloud_key_detected"
    assert rules["DEEPSEEK_API_KEY"] == "nhi_ai_provider_key_detected"
    assert rules["SECRET_KEY"] == "nhi_plaintext_env_secret"


def test_env_parser_suffix_fallback_for_unlisted_keys():
    signals = env_files.parse(Path(".env"), "DEPLOY_AUTH_TOKEN=GNOC_FAKE_SECRET_DO_NOT_USE_654321\n")
    assert signals and signals[0]["rule_id"] == "nhi_plaintext_env_secret"
    assert signals[0]["name"] == "DEPLOY_AUTH_TOKEN"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_654321" not in signals[0]["evidence"][0]


def test_env_parser_suffix_fallback_ignores_non_secret_values():
    text = "BUILD_NUMBER=12345\nSOME_TOKEN=short\nPUBLIC_URL=https://example.com/\n"
    assert env_files.parse(Path(".env"), text) == []


def test_env_parser_connection_string_fallback():
    signals = env_files.parse(Path(".env"), "PAYMENTS_DB_DSN=postgres://svc:GNOC_FAKE_SECRET_DO_NOT_USE_999@db/x\n")
    assert signals and signals[0]["rule_id"] == "nhi_database_url_with_credentials"
    assert signals[0]["name"] == "PAYMENTS_DB_DSN"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_999" not in signals[0]["evidence"][0]


def test_env_parser_redis_url_with_empty_user():
    signals = env_files.parse(Path(".env"), "REDIS_URL=rediss://:GNOC_FAKE_SECRET_DO_NOT_USE_123456@host:6380\n")
    assert any(s["rule_id"] == "nhi_database_url_with_credentials" for s in signals)


def test_env_template_files_emit_low_confidence():
    text = "OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_123456\n"
    template = env_files.parse(Path(".env.example"), text)
    real = env_files.parse(Path(".env"), text)
    assert template[0]["confidence"] == "low"
    assert real[0]["confidence"] == "high"


def test_env_template_files_suppress_production_escalation():
    text = "OPENAI_API_KEY=sk-prod-Ab1Cd2Ef3Gh4Ij5Kl6\n"
    template = env_files.parse(Path(".env.production.example"), text)
    real = env_files.parse(Path(".env.production"), text)
    assert not any(s["rule_id"] == "nhi_production_ai_key_in_env" for s in template)
    assert any(s["rule_id"] == "nhi_production_ai_key_in_env" for s in real)
