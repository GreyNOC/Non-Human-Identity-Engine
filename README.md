# GreyNOC Non-Human Identity Risk Engine

Short name: `greynoc-nhi-engine`

GreyNOC NHI Risk Engine is a local-first defensive application security tool for app developers, SaaS startups, AI app builders, freelance dev agencies, and small product teams.

It scans an app repo or project folder, inventories non-human identities, detects risky secrets and automation identities, scores blast radius, maps findings to OWASP Non-Human Identities Top 10 2025, and generates developer/client-ready reports.

The engine includes an advanced correlation pass that reasons across files instead of treating every match as isolated. It can identify secret sprawl, provider exposure chains, AI-agent-to-MCP privilege bridges, untrusted CI/CD deployment paths, build pipeline secret sinks, shadow admin automation paths, customer-data credential coupling, orphaned identity clusters, and production automation without approval gates.

The scanner is optimized for local developer repos: it prunes ignored directories during traversal, skips large files, caches parser dispatch decisions, and deduplicates repeated parser signals before rule evaluation.

## Why Non-Human Identities Matter

Modern apps ship with API keys, OAuth apps, service accounts, CI/CD tokens, webhooks, browser extension identities, MCP connectors, and AI agent tools. These identities can access code, cloud infrastructure, customer data, deployment systems, email, files, and payments. Before shipping, teams need to know what exists, what it can access, and what should be rotated, scoped, owned, logged, or gated.

## What It Scans

- `.env` and config files
- GitHub Actions workflows
- Docker and Docker Compose
- Terraform
- Kubernetes YAML
- `package.json` scripts
- OAuth app configs
- Cloud credential structures
- Browser extension manifests
- AI agent tool configs
- MCP server configs
- Claude Desktop, Cursor, Windsurf, Continue, Copilot-style, `agents.*`, `crew.py`, AutoGen, CrewAI, LangChain, LlamaIndex, Semantic Kernel, LiteLLM, local model gateway, and OpenAI-compatible gateway configs where present
- Webhook URLs and secrets
- Package registry, deployment platform, monitoring DSN, Bearer, JWT-like, and modern SaaS token patterns

## Identity Categories

Scan output normalizes identities into first-class categories so teams can compare risk across tools and providers:

- `ai_agent`
- `mcp_server`
- `model_gateway`
- `tool_connector`
- `oauth_app`
- `browser_extension`
- `ci_runner`
- `webhook_identity`
- `service_account`
- `cloud_workload_identity`
- `api_key`
- `bot_account`
- `deployment_identity`

Where available, identities include owner, business purpose, expiry, review date, revocation hint, approval requirement, logging status, context store, memory status, tool permissions, scopes, data classes, environment, provider, source file, source line, and confidence.

## AI Agent and MCP Detection

The engine detects AI agent frameworks and configs such as LangChain, LlamaIndex, CrewAI, AutoGen, Semantic Kernel, `agents.yaml`, `agents.json`, `crew.py`, and related tool config files. It also detects MCP server configs including `.mcp.json`, `mcp.json`, Claude Desktop config, Cursor/Windsurf/Continue-style MCP configs, and servers that expose filesystem, shell, terminal, browser, email, Slack, GitHub, Google Drive, database, Kubernetes, Docker, Terraform, AWS, Azure, GCP, Jira, Notion, or calendar capabilities.

MCP commands that execute `python`, `node`, `npx`, `uvx`, `docker`, `bash`, `sh`, `powershell`, or `cmd.exe` are treated as high-risk command runners. Agent or MCP combinations involving filesystem, shell/terminal, GitHub write scopes, sensitive memory/context stores, broad data paths, or model gateway secrets are correlated into stronger findings.

## What It Does Not Do

GreyNOC NHI Risk Engine does not validate credentials, replay tokens, attempt logins, call third-party APIs with discovered keys, crack secrets, exploit systems, escalate privileges, evade detection, exfiltrate data, or perform attack automation.

All detected values are masked. Full secrets are never printed in terminal output, reports, the GUI, exceptions, parser errors, or SQLite.

## Safe Secret Handling

The engine stores only safe evidence: masked secret display, stable secret fingerprint, file path, line number, rule ID, redacted evidence, and identity metadata. It redacts bearer tokens, API keys, private keys, OAuth secrets, webhook secrets, high-entropy strings, and credential assignment lines before data enters reports or persistence. It never validates, replays, or calls out with discovered credentials.

## Install

Python 3.11+ is recommended.

```bash
python -m pip install -e .
```

The app uses the Python standard library plus `pytest` for tests. `rich` is optional for future CLI polish and is not required.

## Run The GUI

```bash
python -m greynoc_nhi --gui
```

The GUI can select a project folder, load the bundled fake sample project, run analysis without freezing, view findings and inventory, and export HTML, JSON, or Markdown reports.

On Windows, `run.bat` launches the GUI by default:

```bat
run.bat
```

## Run The CLI

Scan the bundled fake sample project:

```bash
python -m greynoc_nhi --load-samples --out ./reports
```

Windows batch launcher with CLI arguments:

```bat
run.bat --load-samples --out .\reports
```

Scan a specific project:

```bash
python -m greynoc_nhi --scan ./greynoc_nhi/data/sample_project --out ./reports
```

Generate JSON output:

```bash
python -m greynoc_nhi --json ./greynoc_nhi/data/sample_project
```

Clear local SQLite scan history:

```bash
python -m greynoc_nhi --clear-db
```

CLI scans show a small GreyNOC pixel-cluster activity indicator while work is running. The GUI shows the same style indicator in the action bar during analysis.

## Reports

Reports are generated into `greynoc_nhi/data/reports` by default or into the directory passed with `--out`.

Formats:

- HTML: polished, printable, client-ready
- JSON: structured scan output
- Markdown: developer-friendly summary
- SARIF 2.1.0: code scanning and CI-friendly findings

JSON, HTML, Markdown, and SARIF include identity type, provider, severity, confidence, reason/category, redacted evidence, source file and line, related identities when available, OWASP NHI mapping, remediation, scan trust level, and policy decision.

Generate SARIF:

```bash
python -m greynoc_nhi --scan ./greynoc_nhi/data/sample_project --out ./reports --sarif-out ./reports/greynoc-nhi.sarif
```

## Confidence Scoring

Every identity and finding includes a confidence level:

- `high`: provider-specific token format, private key block, service account JSON, GitHub Actions `write-all`, `pull_request_target` with secrets, Kubernetes `cluster-admin`, Docker socket, high-risk MCP access, broad browser extension background access, CI/CD deployment without approval, or strong AI-agent tool evidence.
- `medium`: generic secret-like values with useful context, known AI framework imports/configs, broad permissions inferred from config, or likely risky automation settings.
- `low`: weak generic patterns, placeholder-like values, test/example contexts, or values that should be reviewed but not treated as confirmed secrets.

Placeholder values such as `changeme`, `replace-me`, `<token>`, `${VAR}`, and `${{ secrets.X }}` are suppressed or downgraded. The bundled `GNOC_FAKE_SECRET_DO_NOT_USE` marker remains detectable so tests and sample data keep working.

Confidence is independent from severity. A weak comment-only or placeholder-style mention should not create a critical finding; severity rises when concrete identity, credential, permission, tool, and data-target signals combine.

## Scan Trust and Policy Decisions

Every scan includes:

- `scan_trust_level`: `clean`, `action_required`, `degraded`, or `untrusted`
- `policy_decision`: `pass`, `manual_review`, or `block`
- `fatal_errors`: redacted fatal execution errors
- `correlation_id`: a per-scan identifier for triage and support

Parser or normalization failures mark a scan as `degraded` so missing findings are not mistaken for clean results. Fatal scanner, correlation, or rule failures mark the scan `untrusted` and default to `block`. Untrusted scans are not persisted unless the engine is explicitly configured to allow untrusted persistence.

## Baselines

Baselines let teams accept existing findings and fail later only on new ones.

Write a baseline:

```bash
python -m greynoc_nhi --scan ./greynoc_nhi/data/sample_project --write-baseline ./greynoc-baseline.json
```

Use a baseline and fail only on new critical findings:

```bash
python -m greynoc_nhi --scan ./greynoc_nhi/data/sample_project --baseline ./greynoc-baseline.json --fail-on-new critical
```

Supported fail severities are `low`, `medium`, `high`, and `critical`.

## .greynocignore

Add a `.greynocignore` file to the project root to skip local-only paths in addition to the built-in ignored directories.

Supported syntax:

```gitignore
# comments and blank lines are ignored
*.pem
testdata/*
samples/*
local-secrets.env
```

The ignore file supports exact file or directory names and simple glob patterns.

## Custom JSON Rule Packs

Custom rule packs let teams add local patterns without adding dependencies or calling external services. JSON is supported now; YAML is future work unless a safe dependency-free subset becomes useful.

Example:

```json
{
  "rules": [
    {
      "id": "company_internal_admin_token",
      "title": "Internal admin token detected",
      "severity": "critical",
      "pattern": "GNOC_ADMIN_[A-Za-z0-9]{24,}",
      "identity_type": "internal admin token",
      "provider": "greynoc",
      "remediation": "Rotate the token and move it to a managed secret store.",
      "confidence": "high"
    }
  ]
}
```

Run with a rule pack:

```bash
python -m greynoc_nhi --scan ./my-project --rules ./greynoc-rules.json --out ./reports
```

Custom rule matches are masked before they enter reports or SQLite.

## CI Example

GitHub Actions example:

```yaml
name: GreyNOC NHI
on: [pull_request]
jobs:
  nhi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -e .
      - run: python -m greynoc_nhi --scan . --out ./reports --sarif-out ./reports/greynoc-nhi.sarif --baseline ./greynoc-baseline.json --fail-on-new critical
```

GreyNOC remains local and defensive in CI: it does not validate credentials, log into services, or call third-party APIs with discovered values.

## Scoring

Scores are deterministic from 0-100:

- 0-19: Clean
- 20-39: Low
- 40-59: Medium
- 60-79: High
- 80-100: Critical

Scoring considers plaintext secrets, production access, admin/cloud/repo permissions, broad OAuth scopes, CI/CD write-all, unpinned actions, AI/MCP tool access, browser session permissions, missing owners, missing logging, missing rotation evidence, private keys, and service account key files.

Advanced correlations add weight when separate findings combine into a larger blast-radius path, such as GitHub Actions write-all plus production secrets plus unpinned actions, or unapproved AI tools plus MCP shell/filesystem access.

Additional correlation examples include AI agent plus filesystem or shell tools, AI agent plus GitHub write scopes, MCP server plus shell/filesystem/browser/email/GDrive/GitHub tools, OAuth app plus broad scopes and no owner, agent memory/context stores that point at sensitive data paths, CI/CD deployment tokens without approval gates, browser extensions with `<all_urls>` and background scripts, unsigned webhooks, multiple NHIs touching the same repository/cloud/data target, and long-lived credentials with no owner or expiry.

## OWASP NHI Top 10 Mapping

Findings map to:

- NHI1:2025 Improper Offboarding
- NHI2:2025 Secret Leakage
- NHI3:2025 Vulnerable Third-Party NHI
- NHI4:2025 Insecure Authentication
- NHI5:2025 Overprivileged NHI
- NHI6:2025 Insecure Cloud Deployment Configurations
- NHI7:2025 Long-Lived Secrets
- NHI8:2025 Environment Isolation
- NHI9:2025 NHI Reuse
- NHI10:2025 Human Use of NHI

## Example Use Cases

- Before shipping an app
- Before client handoff
- Before investor or security review
- After onboarding AI coding agents
- After adding GitHub Actions or cloud deploys

## Screenshots

Screenshots can be added after running the GUI locally.

## Roadmap

- More config-specific parsers
- YAML rule-pack support if it can stay safe and lightweight
- Trend comparison between scans
- More granular ownership workflows

## Defensive Use

Use this tool only against code and systems you own or are authorized to assess. Do not upload real scan outputs publicly.
