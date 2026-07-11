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


# One planted fake token per PATTERNS entry, keyed by pattern name. Every
# pattern must have a fixture here: the end-to-end parse also proves the
# pattern's anchor literals are a superset of the regex (a detection can only
# happen when the anchor gate passed).
PATTERN_FIXTURES: dict[str, tuple[str, str]] = {
    "NPM_TOKEN": ('registry_token = "npm_GNOCFAKEDONOTUSE1234567890"', "nhi_package_registry_token_detected"),
    "PYPI_TOKEN": ('twine_token = "pypi-GNOCFAKEDONOTUSE1234567890"', "nhi_package_registry_token_detected"),
    "VERCEL_TOKEN": ('deploy_token = "vercel_GNOCFAKEDONOTUSE12345"', "nhi_deployment_platform_token_detected"),
    "NETLIFY_TOKEN": ("NETLIFY_AUTH_TOKEN=GNOCFAKEDONOTUSE1234", "nhi_deployment_platform_token_detected"),
    "HUGGINGFACE_TOKEN": ('hub_token = "hf_GNOCFAKEDONOTUSE1234567890"', "nhi_ai_provider_key_detected"),
    "OPENAI_PROJECT_KEY": ('client_key = "sk-proj-GNOCFAKEDONOTUSE1234567890"', "nhi_ai_provider_key_detected"),
    "PULUMI_ACCESS_TOKEN": ('stack_token = "pul-GNOCFAKEDONOTUSE1234567890"', "nhi_secret_leakage"),
    "SENTRY_DSN": ('dsn = "https://GNOCFAKE1234@o12345.ingest.sentry.io/67890"', "nhi_monitoring_dsn_exposed"),
    "GITHUB_FINE_GRAINED_TOKEN": ('gh = "github_pat_GNOCFAKEDONOTUSE1234567890"', "nhi_github_token_detected"),
    "SLACK_APP_TOKEN": ('app_token = "xapp-1-GNOCFAKEDONOTUSE-1234567890"', "nhi_secret_leakage"),
    "SLACK_USER_TOKEN": ('user_token = "xoxp-GNOCFAKEDONOTUSE-1234567890"', "nhi_secret_leakage"),
    "STRIPE_RESTRICTED_KEY": ('restricted = "rk_live_GNOCFAKEDONOTUSE1234"', "nhi_payment_key_detected"),
    "GITHUB_CLASSIC_TOKEN": ('gh_pat = "ghp_GNOCFAKEDONOTUSE1234567890ABCDEFGHIJ"', "nhi_github_token_detected"),
    "GITLAB_PAT": ('gl_token = "glpat-GNOCFAKEDONOTUSE-12345"', "nhi_secret_leakage"),
    "SLACK_BOT_TOKEN": ('bot_token = "xoxb-GNOCFAKEDONOTUSE-1234567890"', "nhi_secret_leakage"),
    "SLACK_WORKSPACE_TOKEN": ('ws_token = "xoxa-GNOCFAKEDONOTUSE-1234567890"', "nhi_secret_leakage"),
    "STRIPE_SECRET_KEY": ('stripe_key = "sk_live_GNOCFAKEDONOTUSE1234"', "nhi_payment_key_detected"),
    "ANTHROPIC_API_KEY": ('client = "sk-ant-api03-GNOCFAKEDONOTUSE123456"', "nhi_ai_provider_key_detected"),
    "OPENAI_SERVICE_ACCOUNT_KEY": ('svc_key = "sk-svcacct-GNOCFAKEDONOTUSE123456"', "nhi_ai_provider_key_detected"),
    "XAI_API_KEY": ('grok_key = "xai-GNOCFAKEDONOTUSE1234567890"', "nhi_ai_provider_key_detected"),
    "GOOGLE_API_KEY": ('maps_key = "AIzaGNOCFAKEDONOTUSE1234567890ABCDEFGHI"', "nhi_cloud_key_detected"),
    "SENDGRID_API_KEY": ('mail_key = "SG.GNOCFAKEDONOTUSE.GNOCFAKEDONOTUSE123456"', "nhi_secret_leakage"),
    # Some fixture literals below are split ("prefix" "body") so the file blob
    # never contains a contiguous provider-token shape: GitHub push protection
    # scans blobs, not runtime values, and would block the push otherwise.
    "DIGITALOCEAN_TOKEN": ('do_token = "dop_v1_' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"', "nhi_cloud_key_detected"),
    "DATABRICKS_TOKEN": ('dbx_token = "dapi' '0123456789abcdef0123456789abcdef"', "nhi_cloud_key_detected"),
    "CLOUDFLARE_API_TOKEN": ('CLOUDFLARE_API_TOKEN="GNOCFAKEDONOTUSE012345678901234567890123"', "nhi_cloud_key_detected"),
    "AZURE_STORAGE_ACCOUNT_KEY": ('conn = "DefaultEndpointsProtocol=https;AccountName=gnoc;AccountKey=GNOCFAKEDONOTUSE0123456789abcdefghijklmnop==;EndpointSuffix=core.windows.net"', "nhi_cloud_key_detected"),
    "TELEGRAM_BOT_TOKEN": ('bot = "123456789:AAGNOCFAKEDONOTUSE0123456789abcdef"', "nhi_secret_leakage"),
    "FLY_API_TOKEN": ('fly_token = "fm2_GNOCFAKEDONOTUSE0123456789abcdefghijklmnop"', "nhi_deployment_platform_token_detected"),
    "DOPPLER_SERVICE_TOKEN": ('doppler = "dp.st.dev.GNOCFAKEDONOTUSE0123456789abcdef"', "nhi_secret_leakage"),
    "LINEAR_API_KEY": ('linear = "lin_api_GNOCFAKEDONOTUSE0123456789abcdef"', "nhi_secret_leakage"),
    "NOTION_INTEGRATION_TOKEN": ('notion = "ntn_' 'GNOCFAKEDONOTUSE0123456789abcdef"', "nhi_secret_leakage"),
    "AIRTABLE_PAT": ('airtable = "patGNOCFAKEDONOTU' '.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"', "nhi_secret_leakage"),
    "TWILIO_API_KEY": ('twilio_sid = "SK' '0123456789abcdef0123456789abcdef"', "nhi_secret_leakage"),
}


def test_every_pattern_has_a_fixture():
    assert {entry[1] for entry in modern_saas.PATTERNS} == set(PATTERN_FIXTURES)


def test_all_pattern_fixtures_detected_and_masked():
    for name, (line, expected_rule) in PATTERN_FIXTURES.items():
        signals = modern_saas.parse(Path("app.py"), line + "\n")
        matched = [signal for signal in signals if signal["name"] == name]
        assert matched, f"{name} fixture produced no signal"
        assert matched[0]["rule_id"] == expected_rule, name
        assert matched[0]["line_number"] == 1, name
        secret = matched[0]["secret_value"]
        assert secret and secret not in matched[0]["evidence"][0], name


def test_pattern_anchor_conventions():
    for entry in modern_saas.PATTERNS:
        anchors = entry[6]
        assert anchors, entry[1]
        assert all(anchor == anchor.lower() for anchor in anchors), entry[1]


def test_notion_internal_secret_format_detected():
    line = 'notion = "secret_' 'GNOCFAKEDONOTUSE1234567890abcdefghijklmnopq"\n'
    signals = modern_saas.parse(Path("app.py"), line)
    assert any(signal["name"] == "NOTION_INTEGRATION_TOKEN" for signal in signals)


def test_twilio_pattern_is_case_sensitive_and_medium_confidence():
    upper = modern_saas.parse(Path("app.py"), 'sid = "SK' '0123456789abcdef0123456789abcdef"\n')
    twilio = [signal for signal in upper if signal["name"] == "TWILIO_API_KEY"]
    assert twilio and twilio[0]["confidence"] == "medium"
    lower = modern_saas.parse(Path("app.py"), 'sid = "sk' '0123456789abcdef0123456789abcdef"\n')
    assert not any(signal["name"] == "TWILIO_API_KEY" for signal in lower)


def test_shell_scripts_are_claimed_and_scanned():
    for filename in ("deploy.sh", "setup.bash", "profile.zsh", "provision.ps1"):
        assert modern_saas.should_parse(Path(filename)), filename
    text = 'export STRIPE_KEY="sk_live_GNOCFAKEDONOTUSE1234"\n'
    signals = modern_saas.parse(Path("deploy.sh"), text)
    assert any(signal["rule_id"] == "nhi_payment_key_detected" for signal in signals)


def test_whole_text_scan_line_numbers_and_order():
    text = (
        "# deploy config\n"
        'stripe = "sk_live_GNOCFAKEDONOTUSE1234"\n'
        "\n"
        'github = "ghp_GNOCFAKEDONOTUSE1234567890ABCDEFGHIJ"\n'
    )
    signals = modern_saas.parse(Path("deploy.sh"), text)
    assert [signal["name"] for signal in signals] == ["STRIPE_SECRET_KEY", "GITHUB_CLASSIC_TOKEN"]
    assert [signal["line_number"] for signal in signals] == [2, 4]
    crlf_signals = modern_saas.parse(Path("deploy.sh"), text.replace("\n", "\r\n"))
    assert [signal["line_number"] for signal in crlf_signals] == [2, 4]


def test_whole_text_scan_same_line_keeps_pattern_order():
    line = 'both = "npm_GNOCFAKEDONOTUSE1234567890 xapp-GNOCFAKEDONOTUSE-1234567890"\n'
    signals = modern_saas.parse(Path("config.txt"), line)
    assert [signal["name"] for signal in signals] == ["NPM_TOKEN", "SLACK_APP_TOKEN"]
    assert all(signal["line_number"] == 1 for signal in signals)


def test_bearer_token_does_not_match_across_lines():
    text = "Authorization:\n  Bearer GNOC_FAKE_BEARER_TOKEN_1234567890\n"
    signals = modern_saas.parse(Path("config.yaml"), text)
    assert not any(signal["rule_id"] == "nhi_bearer_token_detected" for signal in signals)


def test_registry_auth_ignores_oauth_and_preauth_keys():
    text = (
        "oauth: authorization-code-flow-pkce\n"
        'preauth = "long-preauth-handler-name-x"\n'
        "auth_provider: azuread-oidc-flow-123456\n"
    )
    signals = modern_saas.parse(Path("settings.yaml"), text)
    assert not any(signal["rule_id"] == "nhi_encoded_registry_auth_detected" for signal in signals)


def test_registry_auth_ignores_bare_auth_outside_registry_configs():
    signals = modern_saas.parse(Path("client.py"), 'auth = "abc123def456ghi789jkl"\n')
    assert not any(signal["rule_id"] == "nhi_encoded_registry_auth_detected" for signal in signals)


def test_registry_auth_still_fires_in_registry_configs():
    npmrc = "auth=GNOCFAKEDONOTUSE1234\n_auth=GNOCFAKEDONOTUSE5678base64==\n"
    signals = modern_saas.parse(Path(".npmrc"), npmrc)
    registry = [signal for signal in signals if signal["rule_id"] == "nhi_encoded_registry_auth_detected"]
    assert [signal["line_number"] for signal in registry] == [1, 2]


def test_registry_auth_detects_yarn_two_npm_auth_token():
    signals = modern_saas.parse(Path(".yarnrc.yml"), 'npmAuthToken: "GNOCFAKEDONOTUSE1234"\n')
    assert any(signal["rule_id"] == "nhi_encoded_registry_auth_detected" for signal in signals)


def test_registry_auth_token_shape_fires_outside_registry_configs():
    text = 'echo "//registry.npmjs.org/:_authToken=GNOCFAKEDONOTUSE1234" >> .npmrc\n'
    signals = modern_saas.parse(Path("ci.yml"), text)
    assert any(signal["rule_id"] == "nhi_encoded_registry_auth_detected" for signal in signals)


def test_jwt_demo_token_not_flagged():
    demo = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    signals = modern_saas.parse(Path("README.md"), f"Example token: {demo}\n")
    assert not any(signal["rule_id"] == "nhi_jwt_detected" for signal in signals)


def test_connection_string_credentials_detected_and_masked():
    text = (
        "db_url: mongodb+srv://svc:GNOCFAKEDONOTUSE123@cluster0.example.net/app\n"
        "cache: rediss://:GNOCFAKEDONOTUSE456@cache.example.net:6380/0\n"
        "queue: amqp://worker:GNOCFAKEDONOTUSE789@broker.example.net:5672\n"
    )
    signals = modern_saas.parse(Path("services.yaml"), text)
    db_signals = [signal for signal in signals if signal["rule_id"] == "nhi_database_url_with_credentials"]
    assert [signal["line_number"] for signal in db_signals] == [1, 2, 3]
    for signal in db_signals:
        assert signal["secret_value"] not in signal["evidence"][0]


def test_connection_string_placeholder_password_not_flagged():
    text = (
        "local: postgres://app_user:password@localhost:5432/app\n"
        "docs: https://example.com/how-to-connect\n"
    )
    signals = modern_saas.parse(Path("services.yaml"), text)
    assert not any(signal["rule_id"] == "nhi_database_url_with_credentials" for signal in signals)


def test_connection_string_production_marker():
    text = 'db = "postgres://svc:GNOCFAKEDONOTUSE123@db.internal:5432/prod_app"\n'
    signals = modern_saas.parse(Path("app.py"), text)
    db_signals = [signal for signal in signals if signal["rule_id"] == "nhi_database_url_with_credentials"]
    assert db_signals and db_signals[0]["production_access"] is True
