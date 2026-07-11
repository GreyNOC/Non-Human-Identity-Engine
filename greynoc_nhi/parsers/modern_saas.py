"""Modern SaaS, registry, and framework token parser."""

from __future__ import annotations

__version__ = 2

import re
from bisect import bisect_right
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

TEXT_EXTENSIONS = {".env", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".md", ".mdx", ".prompt", ".ipynb", ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".cs", ".tf", ".sh", ".bash", ".zsh", ".ps1"}

# Each entry: (rule_id, name, pattern, identity_type, provider, source_name, anchors, confidence).
# `anchors` are lowercase literal substrings, at least one of which MUST appear
# in any text the pattern can match (patterns are compiled with re.I, so the
# check runs against the lowercased file text). They gate whole-text regex
# passes so files without a vendor marker pay one cheap substring scan instead
# of a regex pass. Whitespace inside patterns uses [^\S\n] so whole-text
# scanning keeps the original per-line matching semantics.
PATTERNS: list[tuple[str, str, str, str, str, str, tuple[str, ...], str | None]] = [
    ("nhi_package_registry_token_detected", "NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{10,}\b", "package registry token", "npm", "package registry", ("npm_",), None),
    ("nhi_package_registry_token_detected", "PYPI_TOKEN", r"\bpypi-[A-Za-z0-9_\-]{20,}\b", "package registry token", "pypi", "package registry", ("pypi-",), None),
    ("nhi_deployment_platform_token_detected", "VERCEL_TOKEN", r"\bvercel_[A-Za-z0-9_\-]{16,}\b|\bVERCEL_TOKEN[^\S\n]*[:=][^\S\n]*['\"]?([^'\"\s,}]+)", "deployment token", "vercel", "deployment platform", ("vercel",), None),
    ("nhi_deployment_platform_token_detected", "NETLIFY_TOKEN", r"\bNETLIFY_AUTH_TOKEN[^\S\n]*[:=][^\S\n]*['\"]?([^'\"\s,}]+)", "deployment token", "netlify", "deployment platform", ("netlify",), None),
    ("nhi_ai_provider_key_detected", "HUGGINGFACE_TOKEN", r"\bhf_[A-Za-z0-9]{20,}\b", "API key", "hugging face", "AI provider", ("hf_",), None),
    ("nhi_ai_provider_key_detected", "OPENAI_PROJECT_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{16,}\b", "API key", "openai", "AI provider", ("sk-proj-",), None),
    ("nhi_secret_leakage", "PULUMI_ACCESS_TOKEN", r"\bpul-[A-Za-z0-9]{20,}\b", "cloud automation token", "pulumi", "IaC platform", ("pul-",), None),
    ("nhi_monitoring_dsn_exposed", "SENTRY_DSN", r"https://[A-Za-z0-9]+@[A-Za-z0-9_.-]+\.ingest\.sentry\.io/[0-9]+", "third-party SaaS integration", "sentry", "monitoring", ("ingest.sentry.io",), None),
    ("nhi_github_token_detected", "GITHUB_FINE_GRAINED_TOKEN", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "GitHub token", "github", "source control", ("github_pat_",), None),
    ("nhi_secret_leakage", "SLACK_APP_TOKEN", r"\bxapp-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration", ("xapp-",), None),
    ("nhi_secret_leakage", "SLACK_USER_TOKEN", r"\bxoxp-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration", ("xoxp-",), None),
    ("nhi_payment_key_detected", "STRIPE_RESTRICTED_KEY", r"\brk_live_[A-Za-z0-9]{16,}\b", "API key", "stripe", "payment", ("rk_live_",), None),
    ("nhi_github_token_detected", "GITHUB_CLASSIC_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token", "github", "source control", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), None),
    ("nhi_secret_leakage", "GITLAB_PAT", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "source control token", "gitlab", "source control", ("glpat-",), None),
    ("nhi_secret_leakage", "SLACK_BOT_TOKEN", r"\bxoxb-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration", ("xoxb-",), None),
    ("nhi_secret_leakage", "SLACK_WORKSPACE_TOKEN", r"\bxox[ar]-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration", ("xoxa-", "xoxr-"), None),
    ("nhi_payment_key_detected", "STRIPE_SECRET_KEY", r"\bsk_live_[A-Za-z0-9]{16,}\b", "API key", "stripe", "payment", ("sk_live_",), None),
    ("nhi_ai_provider_key_detected", "ANTHROPIC_API_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "API key", "anthropic", "AI provider", ("sk-ant-",), None),
    ("nhi_ai_provider_key_detected", "OPENAI_SERVICE_ACCOUNT_KEY", r"\bsk-svcacct-[A-Za-z0-9_\-]{16,}\b", "API key", "openai", "AI provider", ("sk-svcacct-",), None),
    ("nhi_ai_provider_key_detected", "XAI_API_KEY", r"\bxai-[A-Za-z0-9_\-]{20,}\b", "API key", "xai", "AI provider", ("xai-",), None),
    ("nhi_cloud_key_detected", "GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b", "API key", "google", "cloud provider", ("aiza",), None),
    ("nhi_secret_leakage", "SENDGRID_API_KEY", r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b", "API key", "sendgrid", "SaaS integration", ("sg.",), None),
    ("nhi_cloud_key_detected", "DIGITALOCEAN_TOKEN", r"\bdo[por]_v1_[a-f0-9]{64}\b", "API key", "digitalocean", "cloud provider", ("dop_v1_", "doo_v1_", "dor_v1_"), None),
    ("nhi_cloud_key_detected", "DATABRICKS_TOKEN", r"\bdapi[a-f0-9]{32}(?:-\d)?\b", "API key", "databricks", "data platform", ("dapi",), None),
    ("nhi_cloud_key_detected", "CLOUDFLARE_API_TOKEN", r"\bCLOUDFLARE_API_TOKEN[^\S\n]*[:=][^\S\n]*['\"]?([A-Za-z0-9_\-]{40})\b", "API key", "cloudflare", "cloud provider", ("cloudflare_api_token",), None),
    ("nhi_cloud_key_detected", "AZURE_STORAGE_ACCOUNT_KEY", r"\bAccountKey=([A-Za-z0-9+/=]{44,})", "storage account key", "azure", "cloud provider", ("accountkey=",), None),
    ("nhi_secret_leakage", "TELEGRAM_BOT_TOKEN", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{32,34}\b", "bot_account", "telegram", "bot platform", (":aa",), None),
    ("nhi_deployment_platform_token_detected", "FLY_API_TOKEN", r"\bfm2_[A-Za-z0-9+/=,_\-]{40,}", "deployment token", "fly.io", "deployment platform", ("fm2_",), None),
    ("nhi_secret_leakage", "DOPPLER_SERVICE_TOKEN", r"\bdp\.st\.(?:[a-z0-9_\-]+\.)?[A-Za-z0-9]{32,}\b", "service token", "doppler", "secrets manager", ("dp.st.",), None),
    ("nhi_secret_leakage", "LINEAR_API_KEY", r"\blin_api_[A-Za-z0-9]{32,}\b", "API key", "linear", "SaaS integration", ("lin_api_",), None),
    ("nhi_secret_leakage", "NOTION_INTEGRATION_TOKEN", r"\bntn_[A-Za-z0-9]{32,}\b|\bsecret_[A-Za-z0-9]{43}\b", "service account", "notion", "SaaS integration", ("ntn_", "secret_"), None),
    ("nhi_secret_leakage", "AIRTABLE_PAT", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "API key", "airtable", "SaaS integration", ("pat",), None),
    # Twilio API key SIDs are bare SK + 32 hex; the loosest shape here, so it is
    # kept case-sensitive and pinned to medium confidence.
    ("nhi_secret_leakage", "TWILIO_API_KEY", r"(?-i:\bSK[a-f0-9]{32}\b)", "API key", "twilio", "SaaS integration", ("sk",), "medium"),
]

# Compile patterns once at module load. Previously these were recompiled
# (via the re-cache) on every line of every scanned file -- the per-line
# cache lookups dominated scan time on real repos.
_COMPILED_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str, str, tuple[str, ...], str | None]] = [
    (rule_id, name, re.compile(pattern, re.I), identity_type, provider, source_name, anchors, confidence)
    for rule_id, name, pattern, identity_type, provider, source_name, anchors, confidence in PATTERNS
]
_BEARER_RE = re.compile(r"\bAuthorization[^\S\n]*[:=][^\S\n]*['\"]?Bearer[^\S\n]+([A-Za-z0-9_\-.=]{16,})", re.I)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
# Well-known documentation/demo JWT signatures (e.g. the jwt.io examples) that
# show up in READMEs and tests and are never real credentials.
_KNOWN_DEMO_JWT_SIGNATURES = frozenset(
    {
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    }
)
# Inside registry config files a bare `auth`/`_auth` key is registry-credential
# context; the lookbehind keeps `oauth:`/`preauth=` (and `auth_provider`, which
# never has `auth` directly before [:=]) from matching.
_REGISTRY_AUTH_RE = re.compile(r"(?i)(?:_authToken|npmAuthToken|(?<![A-Za-z])_?auth)[^\S\n]*[:=][^\S\n]*['\"]?([A-Za-z0-9_\-/+=]{16,})")
# Outside registry config files only npm-specific key shapes count
# (_auth, _authToken, npmAuthToken), e.g. .npmrc lines echoed in CI YAML.
_NPM_AUTH_RE = re.compile(r"(?i)(?:npm_?authToken|(?<![A-Za-z0-9])_auth(?:Token)?)[^\S\n]*[:=][^\S\n]*['\"]?([A-Za-z0-9_\-/+=]{16,})")
_REGISTRY_CONFIG_NAMES = {".npmrc", ".yarnrc", ".yarnrc.yml", "config.json"}
# URL connection strings with inline credentials (scheme://user:password@host).
_DB_URL_CRED_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|ftp|sftp)://([^:\s/@]{0,64}):([^@\s/]{1,256})@",
    re.I,
)

def should_parse(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {".npmrc", ".yarnrc", "config.json"}

def _build_line_starts(text: str) -> list[int]:
    starts = [0]
    find = text.find
    pos = find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = find("\n", pos + 1)
    return starts

def parse(path: Path, text: str) -> list[Signal]:
    # Whole-text scanning: each pattern runs once over the full text (gated by
    # a cheap substring anchor check), and match offsets are mapped back to
    # line numbers via a bisect over precomputed line-start offsets. This
    # replaces the previous per-line loop that invoked every regex on every
    # line of every file.
    lowered = text.lower()
    line_starts: list[int] | None = None

    def line_number_for(offset: int) -> int:
        nonlocal line_starts
        if line_starts is None:
            line_starts = _build_line_starts(text)
        return bisect_right(line_starts, offset)

    def line_text_for(number: int) -> str:
        starts = line_starts or [0]
        start = starts[number - 1]
        end = starts[number] - 1 if number < len(starts) else len(text)
        return text[start:end]

    # (line_number, branch_order, match_start, kind, value) tuples, sorted
    # before emission so signal order matches the previous per-line loop:
    # per line, PATTERNS matches first (in pattern order), then bearer, JWT,
    # registry auth, and connection-string credentials.
    hits: list[tuple[int, int, int, str, object]] = []
    for index, entry in enumerate(_COMPILED_PATTERNS):
        compiled, anchors = entry[2], entry[6]
        if not any(anchor in lowered for anchor in anchors):
            continue
        for match in compiled.finditer(text):
            value = next((group for group in match.groups() if group), match.group(0))
            if value and looks_like_secret(value):
                hits.append((line_number_for(match.start()), index, match.start(), "pattern", value))
    pattern_count = len(_COMPILED_PATTERNS)
    if "bearer" in lowered:
        bearer_lines: set[int] = set()
        for match in _BEARER_RE.finditer(text):
            number = line_number_for(match.start())
            if number in bearer_lines:
                continue
            bearer_lines.add(number)
            if looks_like_secret(match.group(1)):
                hits.append((number, pattern_count, match.start(), "bearer", match.group(1)))
    if "eyj" in lowered:
        jwt_lines: set[int] = set()
        for match in _JWT_RE.finditer(text):
            number = line_number_for(match.start())
            if number in jwt_lines:
                continue
            jwt_lines.add(number)
            token = match.group(0)
            if token.rsplit(".", 1)[-1] in _KNOWN_DEMO_JWT_SIGNATURES:
                continue
            if not looks_like_secret(token):
                continue
            hits.append((number, pattern_count + 1, match.start(), "jwt", token))
    if "auth" in lowered:
        registry_re = _REGISTRY_AUTH_RE if path.name.lower() in _REGISTRY_CONFIG_NAMES else _NPM_AUTH_RE
        registry_lines: set[int] = set()
        for match in registry_re.finditer(text):
            number = line_number_for(match.start())
            if number in registry_lines:
                continue
            registry_lines.add(number)
            if looks_like_secret(match.group(1)):
                hits.append((number, pattern_count + 2, match.start(), "registry", match.group(1)))
    if "://" in lowered:
        for match in _DB_URL_CRED_RE.finditer(text):
            password = match.group(2)
            if looks_like_secret(password):
                hits.append((line_number_for(match.start()), pattern_count + 3, match.start(), "dburl", password))

    hits.sort(key=lambda item: (item[0], item[1], item[2]))
    signals: list[Signal] = []
    for number, branch, _start, kind, value in hits:
        line = line_text_for(number)
        if kind == "pattern":
            rule_id, name, _compiled, identity_type, provider, source_name, _anchors, confidence = _COMPILED_PATTERNS[branch]
            signals.append(
                make_signal(
                    rule_id=rule_id,
                    file_path=path,
                    line_number=number,
                    name=name,
                    identity_type=identity_type,
                    source=source_name,
                    evidence=line.strip(),
                    secret_value=value,
                    provider=provider,
                    external_access=True,
                    production_access="live" in str(value).lower() or "prod" in line.lower(),
                    tags=["plaintext_secret", "modern_saas"],
                    confidence=confidence,
                )
            )
        elif kind == "bearer":
            signals.append(
                make_signal(
                    rule_id="nhi_bearer_token_detected",
                    file_path=path,
                    line_number=number,
                    name="Authorization Bearer token",
                    identity_type="API key",
                    source="HTTP authorization config",
                    evidence=line.strip(),
                    secret_value=str(value),
                    external_access=True,
                    tags=["plaintext_secret", "http_auth"],
                )
            )
        elif kind == "jwt":
            signals.append(
                make_signal(
                    rule_id="nhi_jwt_detected",
                    file_path=path,
                    line_number=number,
                    name="JWT-like token",
                    identity_type="automation script credential",
                    source="JWT parser",
                    evidence=line.strip(),
                    secret_value=str(value),
                    external_access=True,
                    tags=["plaintext_secret", "jwt"],
                )
            )
        elif kind == "registry":
            signals.append(
                make_signal(
                    rule_id="nhi_encoded_registry_auth_detected",
                    file_path=path,
                    line_number=number,
                    name="Package registry auth",
                    identity_type="package registry token",
                    source="package registry config",
                    evidence=line.strip(),
                    secret_value=str(value),
                    provider="package registry",
                    external_access=True,
                    tags=["plaintext_secret", "package_registry"],
                )
            )
        else:  # dburl
            signals.append(
                make_signal(
                    rule_id="nhi_database_url_with_credentials",
                    file_path=path,
                    line_number=number,
                    name="CONNECTION_URL_CREDENTIALS",
                    identity_type="database connection identity",
                    source="connection string",
                    evidence=line.strip(),
                    secret_value=str(value),
                    provider="database",
                    external_access=True,
                    production_access="prod" in line.lower(),
                    data_access_level="customer",
                    tags=["plaintext_secret", "modern_saas"],
                )
            )
    return signals
