"""Client-ready report generation."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from greynoc_nhi.constants import DEFAULT_REPORTS_DIR
from greynoc_nhi.models import Finding, NonHumanIdentity, ScanResult
from greynoc_nhi.owasp_mapping import describe_ref
from greynoc_nhi.scoring import severity_label
from greynoc_nhi.utils import utc_now


def _ensure_out(out_dir: str | Path | None) -> Path:
    path = Path(out_dir) if out_dir else DEFAULT_REPORTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _join(items: list[str]) -> str:
    return ", ".join(items) if items else "-"


def generate_json_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.json"
    out.write_text(json.dumps(scan.to_dict(), indent=2), encoding="utf-8")
    return out


def generate_markdown_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.md"
    lines = [
        "# GreyNOC Non-Human Identity Risk Engine",
        "",
        f"Project: `{scan.project_path}`",
        f"Scan date: {scan.completed_at}",
        f"Overall risk score: **{scan.overall_score} ({severity_label(scan.overall_score)})**",
        "",
        "## Executive Summary",
        scan.summary,
        "",
        f"- Identities found: {len(scan.identities)}",
        f"- Findings: {len(scan.findings)}",
        f"- Critical findings: {sum(1 for f in scan.findings if f.severity == 'critical')}",
        f"- High findings: {sum(1 for f in scan.findings if f.severity == 'high')}",
        "",
        "## Developer Summary",
        "Fix critical/high findings first, rotate any exposed secrets, reduce broad permissions, and add owners, logging, and approval gates.",
        "",
        "## NHI Inventory",
    ]
    for identity in scan.identities:
        lines.append(f"- **{identity.name}** ({identity.identity_type}) from {identity.source}; provider={identity.provider or '-'}; risk={_join(identity.tags)}; secret={identity.masked_secret or '-'}")
    lines.extend(["", "## Findings"])
    for finding in scan.findings:
        lines.extend([
            f"### {finding.severity.upper()} {finding.title}",
            f"- Score: {finding.risk_score}",
            f"- Rule: `{finding.rule_id}`",
            f"- File: `{finding.file_path or '-'}` line {finding.line_number or '-'}",
            f"- Evidence: {'; '.join(finding.evidence)}",
            f"- Why it matters: {finding.why_it_matters}",
            f"- Remediation: {finding.remediation}",
            f"- OWASP NHI: {_join(finding.owasp_nhi_refs)}",
            "",
        ])
    lines.extend([
        "## 30-Day Remediation Plan",
        "- Day 0-3: rotate exposed critical secrets, remove write-all/admin paths, disable unsafe AI/MCP shell access.",
        "- Day 4-10: revoke or re-scope OAuth, GitHub, cloud, Docker, Kubernetes, and webhook identities.",
        "- Day 11-20: harden CI/CD and cloud deployment configuration.",
        "- Day 21-30: assign owners, document rotation, enable logging, and add approval gates.",
        "",
        "## Safety Disclaimer",
        "This was a local defensive scan. No credential validation was performed and no external systems were accessed.",
    ])
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def _badge(severity: str) -> str:
    return f'<span class="badge {html.escape(severity.lower())}">{html.escape(severity.upper())}</span>'


def _table_rows_identities(identities: list[NonHumanIdentity]) -> str:
    rows = []
    for item in identities:
        risk = ", ".join([tag for tag in item.tags if tag.startswith("nhi_")]) or "-"
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.identity_type)}</td><td>{html.escape(item.source)}</td><td>{html.escape(item.name)}</td>"
            f"<td>{html.escape(item.provider or '-')}</td><td>{html.escape(item.environment or '-')}</td><td>{html.escape(item.owner or '-')}</td>"
            f"<td>{html.escape(_join(item.permissions + item.scopes + item.tools))}</td><td>{html.escape(risk)}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="8">No identities found.</td></tr>'


def _table_rows_findings(findings: list[Finding]) -> str:
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{_badge(finding.severity)}</td><td>{finding.risk_score}</td><td>{html.escape(finding.rule_id)}</td>"
            f"<td>{html.escape(finding.file_path or '-')}</td><td>{finding.line_number or '-'}</td>"
            f"<td>{html.escape('; '.join(finding.evidence))}</td><td>{html.escape(finding.why_it_matters)}</td><td>{html.escape(finding.remediation)}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="8">No findings found.</td></tr>'


def generate_html_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.html"
    owasp_counts = Counter(ref for finding in scan.findings for ref in finding.owasp_nhi_refs)
    themes = Counter(f.category for f in scan.findings).most_common(5)
    blast = {
        "Code access": any("github" in (i.provider or "").lower() or "source-code" == i.data_access_level for i in scan.identities),
        "Cloud access": any("cloud" in (i.provider or "").lower() or "cloud" in i.tags for i in scan.identities),
        "Production access": any(i.production_access for i in scan.identities),
        "Customer data access": any(i.data_access_level == "customer" for i in scan.identities),
        "CI/CD access": any("ci_cd" in i.tags for i in scan.identities),
        "AI tool access": any("ai_agent" in i.tags or i.identity_type == "AI agent tool connector" for i in scan.identities),
        "Browser/session access": any(i.data_access_level == "session" or "browser_extension" in i.tags for i in scan.identities),
    }
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GreyNOC NHI Risk Report</title>
<style>
body {{ margin:0; font-family: Arial, sans-serif; color:#17202a; background:#f5f7f9; }}
header {{ background:#071317; color:#f7fbfc; padding:34px 44px; border-bottom:5px solid #18b985; }}
h1 {{ margin:0; font-size:32px; }} h2 {{ color:#0b2b35; margin-top:34px; }} h3 {{ margin-bottom:8px; }}
.wrap {{ max-width:1180px; margin:0 auto; padding:28px 36px; background:white; }}
.score {{ display:inline-block; padding:10px 16px; border-radius:6px; background:#0d6e7d; color:white; font-weight:700; }}
.grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:22px 0; }}
.card {{ border:1px solid #d8e1e5; border-radius:8px; padding:16px; background:#fbfdfe; }}
.card strong {{ display:block; font-size:26px; color:#0d6e7d; }}
table {{ width:100%; border-collapse:collapse; margin:12px 0 24px; font-size:13px; }}
th,td {{ border:1px solid #d9e3e7; padding:9px; vertical-align:top; }} th {{ background:#eaf4f6; text-align:left; }}
.badge {{ border-radius:4px; padding:4px 7px; color:white; font-size:11px; font-weight:700; }}
.critical {{ background:#b42318; }} .high {{ background:#d04a02; }} .medium {{ background:#b7791f; }} .low {{ background:#237a57; }}
.note {{ background:#edf8f5; border-left:4px solid #18b985; padding:12px 14px; }}
footer {{ color:#52616a; font-size:12px; margin-top:34px; border-top:1px solid #d9e3e7; padding-top:18px; }}
@media print {{ body {{ background:white; }} .wrap {{ padding:0; }} }}
</style>
</head>
<body>
<header><h1>GreyNOC Non-Human Identity Risk Engine</h1><p>Developer-first NHI, secret, OAuth, CI/CD, and AI-agent risk scanner</p><p class="score">Overall Risk: {scan.overall_score} / 100 - {severity_label(scan.overall_score)}</p></header>
<main class="wrap">
<section><h2>Cover Page</h2><p><strong>Project path:</strong> {html.escape(scan.project_path)}<br><strong>Scan date:</strong> {html.escape(scan.completed_at)}</p></section>
<section><h2>Executive Summary</h2><p class="note">{html.escape(scan.summary)}</p><div class="grid">
<div class="card">Identities<strong>{len(scan.identities)}</strong></div><div class="card">Findings<strong>{len(scan.findings)}</strong></div>
<div class="card">Critical<strong>{sum(1 for f in scan.findings if f.severity == 'critical')}</strong></div><div class="card">Advanced<strong>{scan.stats.get('advanced_correlations', 0)}</strong></div></div>
<p><strong>Main risk themes:</strong> {html.escape(', '.join(f'{name} ({count})' for name, count in themes) or 'None')}</p></section>
<section><h2>Developer Summary</h2><p>Fix critical and high issues first, especially exposed secrets, broad CI/CD permissions, admin cloud policies, unsafe MCP connectors, and AI agents with unapproved tools. Medium and low issues can follow as governance hardening.</p></section>
<section><h2>NHI Inventory</h2><table><thead><tr><th>Type</th><th>Source</th><th>Name</th><th>Provider</th><th>Environment</th><th>Owner</th><th>Permissions / Scopes / Tools</th><th>Risk Indicators</th></tr></thead><tbody>{_table_rows_identities(scan.identities)}</tbody></table></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Score</th><th>Rule ID</th><th>File</th><th>Line</th><th>Evidence</th><th>Why It Matters</th><th>Remediation</th></tr></thead><tbody>{_table_rows_findings(scan.findings)}</tbody></table></section>
<section><h2>OWASP NHI Mapping</h2><table><thead><tr><th>Category</th><th>Count</th><th>Explanation</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(ref)}</td><td>{count}</td><td>{html.escape(describe_ref(ref))}</td></tr>' for ref, count in sorted(owasp_counts.items())) or '<tr><td colspan="3">No mapped findings.</td></tr>'}</tbody></table></section>
<section><h2>Blast-Radius View</h2><table><tbody>{''.join(f'<tr><th>{html.escape(name)}</th><td>{"Present" if present else "Not observed"}</td></tr>' for name, present in blast.items())}</tbody></table></section>
<section><h2>30-Day Remediation Plan</h2><ol><li><strong>Day 0-3:</strong> rotate exposed critical secrets and remove write-all/admin paths.</li><li><strong>Day 4-10:</strong> revoke, rotate, and re-scope OAuth, GitHub, cloud, Docker, Kubernetes, and webhook identities.</li><li><strong>Day 11-20:</strong> harden CI/CD and cloud deployments.</li><li><strong>Day 21-30:</strong> assign owners, document rotation, enable logging, and add approval gates.</li></ol></section>
<section><h2>Evidence Appendix</h2><p>All evidence is masked. Full secrets are never displayed, validated, or used.</p></section>
<footer>Safety disclaimer: local defensive scan only. No credential validation performed. No external systems accessed. Generated {html.escape(utc_now())}.</footer>
</main></body></html>"""
    out.write_text(body, encoding="utf-8")
    return out


def generate_all_reports(scan: ScanResult, out_dir: str | Path | None = None) -> dict[str, Path]:
    return {
        "html": generate_html_report(scan, out_dir),
        "json": generate_json_report(scan, out_dir),
        "markdown": generate_markdown_report(scan, out_dir),
    }
