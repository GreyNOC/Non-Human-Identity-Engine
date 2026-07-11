"""Planted/placebo tests for the secrets-focused parser audit fixes.

Covers generic_config (TOML/INI '=' assignments, shell scripts, line-number
parity), cloud_credentials (ASIA keys, PEM variants, azure value gating,
kubeconfig, .aws/credentials, .tfvars, 2024+ cloud token formats), webhooks
(doc-link and valueless-line false positives, whsec_ capture), and
oauth_configs (exact-token broad-scope matching).
"""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers import cloud_credentials, generic_config, oauth_configs, webhooks


# ---------------------------------------------------------------- generic_config

def test_generic_config_toml_equals_assignment():
    text = '[database]\npassword = "GNOC_FAKE_SECRET_DO_NOT_USE_TOML_123456"\n'
    signals = generic_config.parse(Path("settings.toml"), text)
    assert len(signals) == 1
    assert signals[0]["line_number"] == 2
    assert signals[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_TOML_123456"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_TOML_123456" not in signals[0]["evidence"][0]


def test_generic_config_ini_inline_comment_stripped():
    text = "[api]\napi_key = GNOC_FAKE_SECRET_DO_NOT_USE_INI_123456 ; rotate monthly\n"
    signals = generic_config.parse(Path("settings.ini"), text)
    assert len(signals) == 1
    assert signals[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_INI_123456"


def test_generic_config_toml_placebo_non_secret_lines():
    text = '[tool.mypy]\nstrict = true\npassword = "${DB_PASSWORD}"\n'
    assert generic_config.parse(Path("pyproject.toml"), text) == []


def test_generic_config_json_line_numbers_for_multiple_keys():
    text = '{\n  "api_key": "GNOC_FAKE_SECRET_DO_NOT_USE_A_123456",\n  "signing_key": "GNOC_FAKE_SECRET_DO_NOT_USE_B_123456"\n}\n'
    signals = generic_config.parse(Path("config.json"), text)
    by_name = {s["name"]: s["line_number"] for s in signals}
    assert by_name["api_key"] == 2
    assert by_name["signing_key"] == 3


def test_generic_config_parses_shell_scripts():
    text = 'echo deploying\nexport DEPLOY_TOKEN="GNOC_FAKE_SECRET_DO_NOT_USE_SH_123456"\n'
    signals = generic_config.parse(Path("deploy.sh"), text)
    assert len(signals) == 1
    assert signals[0]["line_number"] == 2
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_SH_123456" not in signals[0]["evidence"][0]


def test_generic_config_shell_ignores_env_indirection():
    assert generic_config.parse(Path("deploy.sh"), "export TOKEN=$SECRET_REF\n") == []


def test_generic_config_should_parse_shell_suffixes():
    assert generic_config.should_parse(Path("deploy.sh"))
    assert generic_config.should_parse(Path("provision.ps1"))
    assert not generic_config.should_parse(Path("README.md"))


# ------------------------------------------------------------ cloud_credentials

def test_cloud_detects_asia_temporary_keys():
    signals = cloud_credentials.parse(Path("creds.txt"), "one\nASIAGNOCFAKEKEY01234\n")
    assert signals and signals[0]["rule_id"] == "nhi_cloud_key_detected"
    assert signals[0]["line_number"] == 2


def test_cloud_ignores_truncated_akia_keys():
    assert cloud_credentials.parse(Path("creds.txt"), "AKIASHORT1234\n") == []


def test_cloud_detects_pem_private_key_variants():
    openssh = cloud_credentials.parse(Path("id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
    ec = cloud_credentials.parse(Path("server.pem"), "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n")
    encrypted = cloud_credentials.parse(Path("server.key"), "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----\n")
    for signals in (openssh, ec, encrypted):
        assert any(s["rule_id"] == "nhi_private_key_detected" for s in signals)


def test_cloud_certificate_only_pem_is_silent():
    assert cloud_credentials.parse(Path("ca.pem"), "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n") == []


def test_cloud_should_parse_key_material_files():
    assert cloud_credentials.should_parse(Path("id_rsa"))
    assert cloud_credentials.should_parse(Path("id_ed25519"))
    assert cloud_credentials.should_parse(Path("server.pem"))
    assert cloud_credentials.should_parse(Path("deploy.key"))
    assert cloud_credentials.should_parse(Path("secrets.tfvars"))
    assert cloud_credentials.should_parse(Path("kubeconfig"))
    assert cloud_credentials.should_parse(Path(".aws/credentials"))
    assert cloud_credentials.should_parse(Path("deploy.sh"))
    assert not cloud_credentials.should_parse(Path("README.md"))


def test_azure_triple_without_value_is_silent():
    text = "client_id = settings.client_id\ntenant_id = settings.tenant_id\nclient_secret = settings.client_secret\n"
    assert cloud_credentials.parse(Path("settings.py"), text) == []


def test_azure_triple_with_real_secret_value_fires():
    text = 'client_id = "app"\ntenant_id = "tenant"\nclient_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_AZ_123456"\n'
    signals = cloud_credentials.parse(Path("settings.py"), text)
    azure = [s for s in signals if s["provider"] == "azure"]
    assert azure and azure[0]["rule_id"] == "nhi_cloud_key_detected"
    assert azure[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_AZ_123456"
    assert all("GNOC_FAKE_SECRET_DO_NOT_USE_AZ_123456" not in s["evidence"][0] for s in signals)


def test_kubeconfig_tokens_and_client_key_data():
    text = (
        "apiVersion: v1\n"
        "users:\n"
        "- name: admin\n"
        "  user:\n"
        "    token: GNOC_FAKE_SECRET_DO_NOT_USE_KUBE_123456\n"
        "    client-key-data: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w\n"
    )
    signals = cloud_credentials.parse(Path("kubeconfig"), text)
    rules = [s["rule_id"] for s in signals]
    assert "nhi_bearer_token_detected" in rules
    assert "nhi_private_key_detected" in rules
    assert all("GNOC_FAKE_SECRET_DO_NOT_USE_KUBE_123456" not in s["evidence"][0] for s in signals)


def test_aws_credentials_profile_secret_key():
    text = "[default]\naws_access_key_id = AKIAGNOCFAKEKEY01234\naws_secret_access_key = GNOC_FAKE_SECRET_DO_NOT_USE_AWS_123456\n"
    signals = cloud_credentials.parse(Path(".aws/credentials"), text)
    rules = [s["rule_id"] for s in signals]
    assert rules.count("nhi_cloud_key_detected") == 2
    names = {s["name"] for s in signals}
    assert "aws_secret_access_key [default]" in names


def test_tfvars_secret_assignments():
    text = 'region = "us-east-1"\ndb_password = "GNOC_FAKE_SECRET_DO_NOT_USE_TF_123456"\n'
    signals = cloud_credentials.parse(Path("prod.tfvars"), text)
    assert len(signals) == 1
    assert signals[0]["rule_id"] == "nhi_hardcoded_secret"
    assert signals[0]["line_number"] == 2
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_TF_123456" not in signals[0]["evidence"][0]


def test_cloud_token_formats_2024():
    aiza = "AIzaGNOC_FAKE_SECRET_DO_NOT_USE_1234567"
    dop = "dop_v1_" + "0123456789abcdef" * 4
    dapi = "dapi" + "0123456789abcdef" * 2
    text = f"google = '{aiza}'\ndo = '{dop}'\ndbx = '{dapi}'\n"
    signals = cloud_credentials.parse(Path("tokens.py"), text)
    providers = {s["provider"] for s in signals if s["rule_id"] == "nhi_cloud_key_detected"}
    assert {"google", "digitalocean", "databricks"} <= providers


# --------------------------------------------------------------------- webhooks

def test_webhook_doc_links_are_silent():
    text = "# see https://api.slack.com/messaging/webhooks/overview\n"
    assert webhooks.parse(Path("readme.py"), text) == []


def test_webhook_provider_host_still_detected():
    text = "x\nhttps://hooks.slack.com/services/T000/B000/GNOC_FAKE_SECRET_DO_NOT_USE\n"
    signals = webhooks.parse(Path("hook.txt"), text)
    assert signals[0]["line_number"] == 2
    assert signals[0]["provider"] == "slack"
    assert signals[0]["confidence"] == "high"


def test_webhook_generic_url_requires_secret_segment():
    silent = webhooks.parse(Path("app.py"), 'url = "https://ci.example.com/webhook/handler"\n')
    assert not any(s["name"] == "Webhook URL" for s in silent)
    loud = webhooks.parse(Path("app.py"), 'url = "https://ci.example.com/webhook/GNOC_FAKE_SECRET_DO_NOT_USE_123456"\n')
    assert any(s["name"] == "Webhook URL" and s["confidence"] == "medium" for s in loud)


def test_webhook_valueless_lines_are_silent():
    assert webhooks.parse(Path("app.py"), "# rotate the webhook_secret regularly\n") == []
    assert webhooks.parse(Path("app.py"), 'webhook_secret = os.environ["WEBHOOK_SECRET"]\n') == []


def test_webhook_secret_assignment_detected_and_masked():
    signals = webhooks.parse(Path("app.py"), 'github_webhook_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_WH_123456"\n')
    assert len(signals) == 1
    assert signals[0]["secret_value"] == "GNOC_FAKE_SECRET_DO_NOT_USE_WH_123456"
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_WH_123456" not in signals[0]["evidence"][0]


def test_webhook_whsec_literal_detected():
    signals = webhooks.parse(Path("app.py"), 'stripe_ws = "whsec_GNOCFAKESECRETDONOTUSE1234"\n')
    assert len(signals) == 1
    assert signals[0]["secret_value"] == "whsec_GNOCFAKESECRETDONOTUSE1234"


def test_webhook_should_parse_shell_suffixes():
    assert webhooks.should_parse(Path("deploy.sh"))
    assert webhooks.should_parse(Path("provision.ps1"))


# ---------------------------------------------------------------- oauth_configs

def test_oauth_narrow_scopes_not_flagged():
    text = '{"client_id": "app", "scopes": ["chat:write", "users:read", "repository_projects:read", "miami-datasets"]}'
    signals = oauth_configs.parse(Path("oauth_app.json"), text)
    assert not any(s["rule_id"] == "nhi_broad_oauth_scope" for s in signals)


def test_oauth_broad_scopes_report_actual_tokens():
    text = '{"scopes": ["repo", "admin:org", "chat:write"]}'
    signals = oauth_configs.parse(Path("oauth_app.json"), text)
    scope_signal = next(s for s in signals if s["rule_id"] == "nhi_broad_oauth_scope")
    assert "repo" in scope_signal["scopes"]
    assert "admin:org" in scope_signal["scopes"]
    assert "chat:write" not in scope_signal["scopes"]


def test_oauth_uri_form_scope_flagged():
    text = '{"scopes": ["https://www.googleapis.com/auth/cloud-platform"]}'
    signals = oauth_configs.parse(Path("oauth_config.json"), text)
    assert any(s["rule_id"] == "nhi_broad_oauth_scope" for s in signals)


def test_oauth_client_secret_line_number():
    text = '{\n  "client_secret": "GNOC_FAKE_SECRET_DO_NOT_USE_123456"\n}\n'
    signals = oauth_configs.parse(Path("oauth.json"), text)
    assert signals[0]["rule_id"] == "nhi_oauth_client_secret_present"
    assert signals[0]["line_number"] == 2
