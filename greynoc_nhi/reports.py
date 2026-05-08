"""Client-ready report generation."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from greynoc_nhi.constants import DEFAULT_REPORTS_DIR
from greynoc_nhi.models import Finding, NonHumanIdentity, ScanResult
from greynoc_nhi.ai_mapping import describe_ai_ref
from greynoc_nhi.owasp_mapping import describe_ref
from greynoc_nhi.sarif import generate_sarif_report
from greynoc_nhi.scoring import severity_label
from greynoc_nhi.utils import assert_no_raw_secret_markers, chmod_private_dir, chmod_private_file, utc_now


def _ensure_out(out_dir: str | Path | None) -> Path:
    path = Path(out_dir) if out_dir else DEFAULT_REPORTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    chmod_private_dir(path)
    return path


def _join(items: list[str]) -> str:
    return ", ".join(items) if items else "-"


def generate_json_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.json"
    content = json.dumps(scan.to_dict(), indent=2)
    assert_no_raw_secret_markers(content)
    out.write_text(content, encoding="utf-8")
    chmod_private_file(out)
    return out


def generate_markdown_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.md"
    lines = [
        "# GreyNOC Non-Human Identity Risk Engine",
        "",
        f"Project: `{scan.project_path}`",
        f"Scan date: {scan.completed_at}",
        f"Overall risk score: **{scan.overall_score} ({severity_label(scan.overall_score)})**",
        f"Scan trust level: **{scan.scan_trust_level}**",
        f"Policy decision: **{scan.policy_decision}**",
        f"Correlation ID: `{scan.correlation_id or '-'}`",
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
        lines.append(f"- **{identity.name}** ({identity.identity_type}) from {identity.source}; provider={identity.provider or '-'}; source={identity.source_file or '-'}:{identity.source_line or '-'}; risk={_join(identity.tags)}; ai={_join(identity.ai_risk_refs)}; secret={identity.masked_secret or '-'}")
    if scan.risk_paths:
        lines.extend(["", "## AI Action Paths"])
        for risk_path in scan.risk_paths:
            lines.append(f"- **{risk_path.attack_class}**: {risk_path.source} -> {risk_path.agent or '-'} -> {risk_path.tool or '-'} -> {risk_path.sink}; boundary={risk_path.trust_boundary}; evidence={'; '.join(risk_path.evidence)}")
    lines.extend(["", "## Findings"])
    for finding in scan.findings:
        lines.extend([
            f"### {finding.severity.upper()} {finding.title}",
            f"- Score: {finding.risk_score}",
            f"- Confidence: {finding.confidence}",
            f"- Category: {finding.category}",
            f"- Baseline: {finding.baseline_status}",
            f"- Priority: {finding.priority}",
            f"- Rule: `{finding.rule_id}`",
            f"- File: `{finding.file_path or '-'}` line {finding.line_number or '-'}",
            f"- Evidence: {'; '.join(finding.evidence)}",
            f"- Related identities: {_join(finding.related_identities)}",
            f"- Why it matters: {finding.why_it_matters}",
            f"- Remediation: {finding.remediation}",
            f"- Control hints: {_join(finding.control_hints)}",
            f"- OWASP NHI: {_join(finding.owasp_nhi_refs)}",
            f"- AI risk refs: {_join(finding.ai_risk_refs)}",
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
    content = "\n".join(lines)
    assert_no_raw_secret_markers(content)
    out.write_text(content, encoding="utf-8")
    chmod_private_file(out)
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
            f"<td>{html.escape(item.source_file or '-')}:{item.source_line or '-'}</td><td>{html.escape(_join(item.permissions + item.scopes + item.tools))}</td><td>{html.escape(risk)}</td><td>{html.escape(_join(item.ai_risk_refs))}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="10">No identities found.</td></tr>'


def _table_rows_findings(findings: list[Finding]) -> str:
    rows = []
    for finding in findings:
        severity = html.escape(finding.severity.lower())
        rows.append(
            f'<tr data-severity="{severity}">'
            f"<td>{_badge(finding.severity)}</td><td>{finding.risk_score}</td><td>{html.escape(finding.confidence)}</td><td>{html.escape(finding.baseline_status)}</td><td>{html.escape(finding.rule_id)}</td>"
            f"<td>{html.escape(finding.category)}</td><td>{html.escape(finding.file_path or '-')}</td><td>{finding.line_number or '-'}</td>"
            f"<td>{html.escape('; '.join(finding.evidence))}</td><td>{html.escape(_join(finding.related_identities))}</td><td>{html.escape(finding.why_it_matters)}</td><td>{html.escape(finding.remediation)}</td><td>{html.escape(_join(finding.control_hints))}</td><td>{html.escape(_join(finding.owasp_nhi_refs))}</td><td>{html.escape(_join(finding.ai_risk_refs))}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="15">No findings found.</td></tr>'


def _table_rows_risk_paths(scan: ScanResult) -> str:
    rows = []
    for path in scan.risk_paths:
        rows.append(
            "<tr>"
            f"<td>{html.escape(path.attack_class)}</td><td>{html.escape(path.source)}</td><td>{html.escape(path.agent or '-')}</td>"
            f"<td>{html.escape(path.tool or '-')}</td><td>{html.escape(path.credential or '-')}</td><td>{html.escape(path.sink)}</td>"
            f"<td>{html.escape(path.trust_boundary)}</td><td>{html.escape('; '.join(path.evidence))}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="8">No AI action paths found.</td></tr>'


INTERACTIVE_JS = """
<script>
(function () {
  function makeSortable(table) {
    var headers = table.querySelectorAll('thead th');
    headers.forEach(function (th, idx) {
      th.style.cursor = 'pointer';
      th.title = 'Click to sort';
      var direction = 1;
      th.addEventListener('click', function () {
        var tbody = table.tBodies[0];
        if (!tbody) return;
        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
          var ax = (a.cells[idx] || {}).innerText || '';
          var bx = (b.cells[idx] || {}).innerText || '';
          var an = parseFloat(ax);
          var bn = parseFloat(bx);
          if (!isNaN(an) && !isNaN(bn)) return (an - bn) * direction;
          return ax.localeCompare(bx) * direction;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
        direction = -direction;
      });
    });
  }
  function attachFilters(table) {
    if (!table.parentNode) return;
    var wrap = document.createElement('div');
    wrap.className = 'gnoc-filters';
    wrap.style.margin = '8px 0';
    var search = document.createElement('input');
    search.type = 'search';
    search.placeholder = 'Search this table...';
    search.style.padding = '6px 8px';
    search.style.marginRight = '8px';
    search.style.minWidth = '240px';
    var sev = document.createElement('select');
    var options = ['all', 'critical', 'high', 'medium', 'low'];
    options.forEach(function (opt) {
      var o = document.createElement('option');
      o.value = opt;
      o.textContent = opt === 'all' ? 'All severities' : opt;
      sev.appendChild(o);
    });
    sev.style.padding = '6px 8px';
    var count = document.createElement('span');
    count.style.marginLeft = '12px';
    count.style.color = '#52616a';
    wrap.appendChild(search);
    wrap.appendChild(sev);
    wrap.appendChild(count);
    table.parentNode.insertBefore(wrap, table);
    function apply() {
      var q = search.value.toLowerCase();
      var s = sev.value;
      var visible = 0;
      var tbody = table.tBodies[0];
      if (!tbody) return;
      Array.prototype.slice.call(tbody.rows).forEach(function (row) {
        var rowSev = (row.getAttribute('data-severity') || '').toLowerCase();
        var matchSev = s === 'all' || rowSev === s;
        var matchSearch = !q || row.innerText.toLowerCase().indexOf(q) !== -1;
        var show = matchSev && matchSearch;
        row.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      count.textContent = visible + ' row(s) shown';
    }
    search.addEventListener('input', apply);
    sev.addEventListener('change', apply);
    apply();
  }
  function init() {
    var tables = document.querySelectorAll('table');
    tables.forEach(function (table) {
      makeSortable(table);
      var hasSeverity = table.querySelector('tbody tr[data-severity]');
      if (hasSeverity) {
        attachFilters(table);
      }
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
</script>
"""


def generate_html_report(scan: ScanResult, out_dir: str | Path | None = None) -> Path:
    out = _ensure_out(out_dir) / f"{scan.scan_id}.html"
    owasp_counts = Counter(ref for finding in scan.findings for ref in finding.owasp_nhi_refs)
    ai_counts = Counter(ref for finding in scan.findings for ref in finding.ai_risk_refs)
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
<section><h2>Cover Page</h2><p><strong>Project path:</strong> {html.escape(scan.project_path)}<br><strong>Scan date:</strong> {html.escape(scan.completed_at)}<br><strong>Scan trust level:</strong> {html.escape(scan.scan_trust_level)}<br><strong>Policy decision:</strong> {html.escape(scan.policy_decision)}<br><strong>Correlation ID:</strong> {html.escape(scan.correlation_id or '-')}</p></section>
<section><h2>Executive Summary</h2><p class="note">{html.escape(scan.summary)}</p><div class="grid">
<div class="card">Identities<strong>{len(scan.identities)}</strong></div><div class="card">Findings<strong>{len(scan.findings)}</strong></div>
<div class="card">Critical<strong>{sum(1 for f in scan.findings if f.severity == 'critical')}</strong></div><div class="card">Trust<strong>{html.escape(scan.scan_trust_level)}</strong></div></div>
<p><strong>Main risk themes:</strong> {html.escape(', '.join(f'{name} ({count})' for name, count in themes) or 'None')}</p></section>
<section><h2>Developer Summary</h2><p>Fix critical and high issues first, especially exposed secrets, broad CI/CD permissions, admin cloud policies, unsafe MCP connectors, and AI agents with unapproved tools. Medium and low issues can follow as governance hardening.</p></section>
<section><h2>NHI Inventory</h2><table><thead><tr><th>Type</th><th>Source</th><th>Name</th><th>Provider</th><th>Environment</th><th>Owner</th><th>Source Location</th><th>Permissions / Scopes / Tools</th><th>Risk Indicators</th><th>AI Refs</th></tr></thead><tbody>{_table_rows_identities(scan.identities)}</tbody></table></section>
<section><h2>AI Action Paths</h2><table><thead><tr><th>Attack Class</th><th>Source</th><th>Agent</th><th>Tool</th><th>Credential</th><th>Sink</th><th>Trust Boundary</th><th>Evidence</th></tr></thead><tbody>{_table_rows_risk_paths(scan)}</tbody></table></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Score</th><th>Confidence</th><th>Baseline</th><th>Rule ID</th><th>Category</th><th>File</th><th>Line</th><th>Evidence</th><th>Related</th><th>Why It Matters</th><th>Remediation</th><th>Controls</th><th>OWASP</th><th>AI Refs</th></tr></thead><tbody>{_table_rows_findings(scan.findings)}</tbody></table></section>
<section><h2>OWASP NHI Mapping</h2><table><thead><tr><th>Category</th><th>Count</th><th>Explanation</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(ref)}</td><td>{count}</td><td>{html.escape(describe_ref(ref))}</td></tr>' for ref, count in sorted(owasp_counts.items())) or '<tr><td colspan="3">No mapped findings.</td></tr>'}</tbody></table></section>
<section><h2>AI Risk Mapping</h2><table><thead><tr><th>Reference</th><th>Count</th><th>Explanation</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(ref)}</td><td>{count}</td><td>{html.escape(describe_ai_ref(ref))}</td></tr>' for ref, count in sorted(ai_counts.items())) or '<tr><td colspan="3">No mapped findings.</td></tr>'}</tbody></table></section>
<section><h2>Blast-Radius View</h2><table><tbody>{''.join(f'<tr><th>{html.escape(name)}</th><td>{"Present" if present else "Not observed"}</td></tr>' for name, present in blast.items())}</tbody></table></section>
<section><h2>30-Day Remediation Plan</h2><ol><li><strong>Day 0-3:</strong> rotate exposed critical secrets and remove write-all/admin paths.</li><li><strong>Day 4-10:</strong> revoke, rotate, and re-scope OAuth, GitHub, cloud, Docker, Kubernetes, and webhook identities.</li><li><strong>Day 11-20:</strong> harden CI/CD and cloud deployments.</li><li><strong>Day 21-30:</strong> assign owners, document rotation, enable logging, and add approval gates.</li></ol></section>
<section><h2>Evidence Appendix</h2><p>All evidence is masked. Full secrets are never displayed, validated, or used.</p></section>
<footer>Safety disclaimer: local defensive scan only. No credential validation performed. No external systems accessed. Generated {html.escape(utc_now())}.</footer>
</main>{INTERACTIVE_JS}</body></html>"""
    assert_no_raw_secret_markers(body)
    out.write_text(body, encoding="utf-8")
    chmod_private_file(out)
    return out


def generate_all_reports(scan: ScanResult, out_dir: str | Path | None = None) -> dict[str, Path]:
    return {
        "html": generate_html_report(scan, out_dir),
        "json": generate_json_report(scan, out_dir),
        "markdown": generate_markdown_report(scan, out_dir),
    }
