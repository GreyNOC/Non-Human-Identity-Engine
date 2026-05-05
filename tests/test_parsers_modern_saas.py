from pathlib import Path

from greynoc_nhi.parsers import modern_saas


def test_modern_saas_detects_package_registry_token():
    signals = modern_saas.parse(Path(".npmrc"), "//registry.npmjs.org/:_authToken=npm_GNOCFAKEDONOTUSE1234567890\n")
    assert any(signal["rule_id"] == "nhi_package_registry_token_detected" for signal in signals)
    assert "GNOCFAKEDONOTUSE1234567890" not in signals[0]["evidence"][0]


def test_modern_saas_detects_bearer_and_jwt_tokens():
    text = (
        "Authorization: Bearer GNOC_FAKE_BEARER_TOKEN_1234567890\n"
        "token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJncmV5bm9jIn0.GNOCFAKEDONOTUSEJWT123456\n"
    )
    signals = modern_saas.parse(Path("config.txt"), text)
    rule_ids = {signal["rule_id"] for signal in signals}
    assert "nhi_bearer_token_detected" in rule_ids
    assert "nhi_jwt_detected" in rule_ids
