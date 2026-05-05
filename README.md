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
- Webhook URLs and secrets
- Package registry, deployment platform, monitoring DSN, Bearer, JWT-like, and modern SaaS token patterns

## What It Does Not Do

GreyNOC NHI Risk Engine does not validate credentials, replay tokens, attempt logins, call third-party APIs with discovered keys, crack secrets, exploit systems, escalate privileges, evade detection, exfiltrate data, or perform attack automation.

All detected values are masked. Full secrets are never printed in terminal output, reports, the GUI, or SQLite.

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

## Scoring

Scores are deterministic from 0-100:

- 0-19: Clean
- 20-39: Low
- 40-59: Medium
- 60-79: High
- 80-100: Critical

Scoring considers plaintext secrets, production access, admin/cloud/repo permissions, broad OAuth scopes, CI/CD write-all, unpinned actions, AI/MCP tool access, browser session permissions, missing owners, missing logging, missing rotation evidence, private keys, and service account key files.

Advanced correlations add weight when separate findings combine into a larger blast-radius path, such as GitHub Actions write-all plus production secrets plus unpinned actions, or unapproved AI tools plus MCP shell/filesystem access.

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
- SARIF export
- Optional custom rule packs
- Trend comparison between scans
- More granular ownership workflows

## Defensive Use

Use this tool only against code and systems you own or are authorized to assess. Do not upload real scan outputs publicly.
