"""Tests for the Helm values.yaml parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import helm


def test_should_parse_values_files() -> None:
    assert helm.should_parse(Path("values.yaml")) is True
    assert helm.should_parse(Path("values-prod.yaml")) is True
    assert helm.should_parse(Path("my-app.values.yaml")) is True
    assert helm.should_parse(Path("Chart.yaml")) is False
    assert helm.should_parse(Path("templates/deployment.yaml")) is False


def test_detects_plaintext_api_key() -> None:
    text = """
imagePullSecrets:
  - name: dockerhub
api:
  apiKey: GNOC_FAKE_SECRET_DO_NOT_USE_HELMKEY_887766
  baseUrl: https://api.example.com
"""
    signals = helm.parse(Path("values.yaml"), text)
    assert any(s["rule_id"] == "nhi_helm_values_plaintext_secret" for s in signals)
    assert any(s["name"] == "apiKey" for s in signals)


def test_detects_database_password() -> None:
    text = """
postgres:
  password: GNOC_FAKE_SECRET_DO_NOT_USE_DBPW_445566
"""
    signals = helm.parse(Path("values.yaml"), text)
    assert any(s["rule_id"] == "nhi_helm_values_plaintext_secret" for s in signals)


def test_skips_template_references() -> None:
    text = """
api:
  apiKey: {{ .Values.global.apiKey }}
  password: $REAL_SECRET
"""
    signals = helm.parse(Path("values.yaml"), text)
    assert signals == []


def test_marks_production_for_prod_filename() -> None:
    text = "api:\n  apiKey: GNOC_FAKE_SECRET_DO_NOT_USE_HELMPROD_111122\n"
    signals = helm.parse(Path("values-production.yaml"), text)
    assert signals
    assert signals[0]["production_access"] is True


def test_detects_inline_dockerconfigjson() -> None:
    text = """
imagePullSecrets:
  - name: regcred
dockercreds:
  dockerconfigjson: ewogICJhdXRocyI6IHsKICAgICJyZWdpc3RyeS5leGFtcGxlLmNvbSI6IHsKICAgICAgImF1dGgiOiAiR05PQ19GQUtFX1NFQ1JFVCIKICAgIH0KICB9Cn0=
"""
    signals = helm.parse(Path("values.yaml"), text)
    assert any(s["rule_id"] == "nhi_helm_values_image_pull_secret_inline" for s in signals)
