# Changelog

## 0.2.0

Performance and detection-quality overhaul (128 audited fixes across scanner, parsers, rules, masking, storage, and outputs). On the bundled synthetic benchmark: directory traversal 32x faster, full scan 2-3x faster, planted-secret recall 64% -> 100%, placebo false positives -65%, clean-corpus noise findings -99%.

Detection:
- New provider token patterns: Stripe live keys, SendGrid, DigitalOcean, Databricks, Cloudflare, Azure storage account keys, Telegram, Fly.io, Doppler, Linear, xAI, Notion, Airtable, extra GitHub/Slack token families, and credentialed database/AMQP/Redis connection strings.
- Secret detection now reaches shell scripts, PowerShell, PEM/OpenSSH key files, kubeconfig, .tfvars, .aws/credentials, .git-credentials, Jenkinsfiles, and bitbucket-pipelines.yml.
- env parsing handles export prefixes and suffix-matched secret names (`*_TOKEN`, `*_SECRET`, ...); AWS regex covers ASIA/ABIA/ACCA temporary key prefixes.
- 25 previously orphaned parser rule ids registered in the rule catalog (they used to silently degrade); a regression test now enforces registration.
- New CI/CD and supply-chain rules: GitHub Actions expression injection, pull_request_target untrusted checkout, secrets: inherit, self-hosted runners, GitLab debug tracing and privileged DinD, Docker/npm/CI curl|sh remote-script execution, Kubernetes inline env secrets, Terraform provisioners, Jenkins/CircleCI coverage, remote MCP servers (HTTP/SSE with auth headers), 2025 agent-framework and MCP config shapes, git-history secrets still present in the working tree.
- Calibration: placeholder/example values (.env.example, your-token-here, sk_test_, all-x runs) drop to low confidence and no longer fuel critical correlations; first-party unpinned actions, Helm secret name references, RAG substring markers, and stock PAM lines no longer create noise.

Performance:
- os.scandir traversal with DirEntry reuse (resolve() only for directories), precompiled ignore patterns, single-read file loading.
- Whole-text anchored regex scanning in hot parsers instead of per-line pattern loops; JSON parsed once per file; bisect line indexes.
- Persistent parser-cache connection; cache keys now include parser dispatch and sanitizer version (prevents cross-filename result poisoning).
- Diff mode validates only changed paths instead of walking the whole tree; batched git blame for owner enrichment; single git log pass with -U0.

Correctness and safety:
- Storage rows are scoped by (scan_id, id) - fixes silent cross-scan row theft corrupting history/trend; v1 schema migration included; WAL journal mode.
- Untrusted (fatally errored) scans now fail closed under --fail-on-new/--severity-exit-codes (exit 10); config errors exit 3.
- Masking hardened: AWS-style and JSON-quoted key assignments now redact correctly; file paths and commit SHAs are no longer over-masked; placeholders survive redaction for readable reports.
- SARIF output uses relative URIs with uriBaseId, security-severity, and stable partialFingerprints.

Hardening (post-implementation adversarial review):
- Secret redaction never skips masking based on content placeholder heuristics; only zero-entropy structural placeholders (env refs, whole-string tokens/phrases) stay readable, so a real secret containing "example"/"dummy"/"_here" can no longer leak into reports.
- Placeholder classification is layered: is_structural_placeholder (redaction-safe) / is_placeholder_value (strong suppression, e.g. "your-token-here") / is_weak_placeholder_value (confidence-only). Passphrase-style credentials ("Correct-Horse-Sample-Staple") are detected and masked; only phrases with an explicit fill-in marker segment ("your", "example") or leading imperative ("replace_", "insert_") are suppressed.
- .greynocignore globbing matches gitignore segment semantics: `*`/`?` do not cross `/`, and `**` matches whole directory segments (no partial-filename under-scan).
- Read-only legacy databases degrade to read-only instead of crashing on migration; the migration uses BEGIN IMMEDIATE with an in-transaction version re-check; a fresh DB whose write lock is held re-raises rather than leaving an unusable connection.
- `--rules` fails closed (exit 3) when the pack is missing, malformed, or loads zero valid rules; `--write-baseline` refuses to overwrite from an untrusted scan; the best-effort trend diagnostic goes to stderr so `--json` stdout stays clean.

Tooling:
- benchmarks/: synthetic corpus generator and timing/recall scorecard runner.
- Test suite grew from 157 to 489 tests, including a dedicated review-regression suite.

## 0.1.0

- Initial local-first GreyNOC NHI Risk Engine.
- Added Tkinter GUI, CLI, SQLite persistence, parser suite, OWASP NHI mapping, scoring, reports, sample project, and pytest coverage.
