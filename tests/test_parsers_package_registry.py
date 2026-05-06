"""Tests for the package-registry credential parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import package_registry


def test_should_parse_known_files() -> None:
    assert package_registry.should_parse(Path(".npmrc")) is True
    assert package_registry.should_parse(Path(".pypirc")) is True
    assert package_registry.should_parse(Path(".netrc")) is True
    assert package_registry.should_parse(Path("gradle.properties")) is True
    assert package_registry.should_parse(Path(".cargo/credentials")) is True
    assert package_registry.should_parse(Path(".gradle/gradle.properties")) is True
    assert package_registry.should_parse(Path("README.md")) is False


def test_npmrc_token_detected() -> None:
    text = """
//registry.npmjs.org/:_authToken=npm_GNOC_FAKE_SECRET_DO_NOT_USE_NPM_887766
@scope:registry=https://registry.example.com/
"""
    signals = package_registry.parse(Path(".npmrc"), text)
    assert any(s["rule_id"] == "nhi_npm_registry_token_in_npmrc" for s in signals)


def test_npmrc_no_signal_for_env_reference() -> None:
    text = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"
    signals = package_registry.parse(Path(".npmrc"), text)
    assert signals == []


def test_pypirc_token_detected() -> None:
    text = """
[distutils]
index-servers = pypi

[pypi]
username = __token__
password = pypi-AgENdGVzdC5GTk9DX0ZBS0VfU0VDUkVUX0RPX05PVF9VU0VfUFlQSV85ODg3NzY2
"""
    signals = package_registry.parse(Path(".pypirc"), text)
    assert any(s["rule_id"] == "nhi_pypi_token_in_pypirc" for s in signals)


def test_cargo_credentials_token() -> None:
    text = """
[registry]
token = "GNOC_FAKE_SECRET_DO_NOT_USE_CARGO_223344"

[registries.example]
token = "GNOC_FAKE_SECRET_DO_NOT_USE_CARGO_REG_445566"
"""
    signals = package_registry.parse(Path(".cargo/credentials"), text)
    rule_ids = [s["rule_id"] for s in signals]
    assert rule_ids.count("nhi_cargo_registry_token") == 2


def test_gradle_properties_token() -> None:
    text = """
ARTIFACTORY_USER=alice
ARTIFACTORY_PASSWORD=GNOC_FAKE_SECRET_DO_NOT_USE_GRADLE_998877
nexus_token=GNOC_FAKE_SECRET_DO_NOT_USE_NEXUS_887766
"""
    signals = package_registry.parse(Path(".gradle/gradle.properties"), text)
    rules = [s["rule_id"] for s in signals]
    assert rules.count("nhi_gradle_repository_credential") == 2


def test_netrc_password_detected() -> None:
    text = """
machine api.example.com
  login alice
  password GNOC_FAKE_SECRET_DO_NOT_USE_NETRC_555566
"""
    signals = package_registry.parse(Path(".netrc"), text)
    assert any(s["rule_id"] == "nhi_netrc_credential" for s in signals)
