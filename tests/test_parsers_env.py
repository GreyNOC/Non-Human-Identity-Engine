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
