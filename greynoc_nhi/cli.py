"""Command-line interface for GreyNOC NHI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from greynoc_nhi.baseline import has_new_findings_at_or_above, read_baseline, write_baseline
from greynoc_nhi.constants import DEFAULT_DB_PATH
from greynoc_nhi.engine import Engine
from greynoc_nhi.indicators import with_cli_indicator
from greynoc_nhi.reports import generate_all_reports, generate_json_report
from greynoc_nhi.sarif import generate_sarif_report
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.scoring import severity_label
from greynoc_nhi.storage import clear_all


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GreyNOC Non-Human Identity Risk Engine")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter GUI")
    parser.add_argument("--scan", help="Scan a project folder")
    parser.add_argument("--load-samples", action="store_true", help="Scan bundled fake sample project")
    parser.add_argument("--out", default=None, help="Output reports directory")
    parser.add_argument("--json", dest="json_path", help="Scan a project and print JSON path/result")
    parser.add_argument("--clear-db", action="store_true", help="Clear local SQLite scan history")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    parser.add_argument("--sarif-out", help="Write SARIF 2.1.0 report to this file or directory")
    parser.add_argument("--baseline", help="Baseline JSON file used to mark known findings")
    parser.add_argument("--write-baseline", help="Write a baseline JSON file from the current scan")
    parser.add_argument("--fail-on-new", choices=["low", "medium", "high", "critical"], help="Return nonzero if a new finding at or above this severity exists")
    parser.add_argument("--rules", help="Custom JSON rule pack path")
    parser.add_argument("--scan-history", action="store_true", help="Also scan git history for secrets that were committed and later removed")
    parser.add_argument("--history-only", action="store_true", help="Skip the working tree and scan only git history")
    parser.add_argument("--history-max-commits", type=int, default=1000, help="Cap history scan to the most recent N commits (default 1000, 0 for unlimited)")
    parser.add_argument("--history-since", help="Only include commits newer than this (e.g. '2024-01-01' or '6 months ago')")
    parser.add_argument("--diff", action="store_true", help="Scan only files changed in <base>...HEAD (default base origin/main)")
    parser.add_argument("--diff-staged", action="store_true", help="Scan only files staged for commit (use in pre-commit hooks)")
    parser.add_argument("--base", default="origin/main", help="Base ref for --diff (default origin/main)")
    parser.add_argument("--host-audit", action="store_true", help="Run a read-only host audit instead of a repo scan")
    parser.add_argument("--linux-auth-audit", action="store_true", help="Audit Linux PAM/SSH auth paths under --host-root")
    parser.add_argument("--host-root", default="/", help="Host root to inspect for --host-audit/--linux-auth-audit (default /)")
    parser.add_argument("--no-elf-strings", action="store_true", help="Skip bounded string extraction from PAM .so files during host audit")
    parser.add_argument("--install-hook", metavar="REPO", nargs="?", const=".", help="Install a git pre-commit hook into REPO (default: current directory)")
    parser.add_argument("--uninstall-hook", metavar="REPO", nargs="?", const=".", help="Remove the GreyNOC NHI pre-commit hook from REPO")
    parser.add_argument("--install-hook-framework", action="store_true", help="Also write .pre-commit-hooks.yaml when installing the hook")
    parser.add_argument("--install-hook-force", action="store_true", help="Reinstall the hook even if already present")
    parser.add_argument("--no-cache", action="store_true", help="Disable the per-file parser output cache")
    parser.add_argument("--clear-cache", action="store_true", help="Drop all cached parser results before scanning")
    parser.add_argument("--no-owner-enrich", action="store_true", help="Skip git blame + CODEOWNERS owner lookup (faster on large diffs)")
    parser.add_argument("--trend", action="store_true", help="Print new/resolved/unchanged finding counts vs the prior scan of this project")
    parser.add_argument(
        "--severity-exit-codes",
        action="store_true",
        help="Use tiered exit codes (0=clean, 1=low/medium, 2=high/critical, 10=untrusted) instead of the binary --fail-on-new code",
    )
    parser.add_argument("--fix-gitignore", metavar="REPO", nargs="?", const=".", help="Add .env-style ignores to REPO's .gitignore")
    parser.add_argument("--fix-pin-actions", metavar="REPO", nargs="?", const=".", help="Pin unpinned third-party GitHub actions to their current SHA via git ls-remote")
    parser.add_argument("--suggest-fix", action="store_true", help="Print fix preview without writing changes")
    return parser


def print_summary(result, reports: dict[str, Path] | None = None, trend=None) -> None:
    print("Scan completed")
    print(f"Overall score: {result.overall_score}")
    print(f"Severity label: {severity_label(result.overall_score)}")
    print(f"Scan trust level: {result.scan_trust_level}")
    print(f"Policy decision: {result.policy_decision}")
    print(f"Identities found: {len(result.identities)}")
    print(f"Findings count: {len(result.findings)}")
    print(f"Advanced correlations: {result.stats.get('advanced_correlations', 0)}")
    if trend is not None:
        print(trend.summary())
    if reports:
        for report_type, path in reports.items():
            print(f"{report_type.upper()} report: {path}")


def _post_process(scan_result, args) -> tuple[object, dict[str, Path]]:
    reports = generate_all_reports(scan_result, args.out)
    if args.sarif_out:
        reports["sarif"] = generate_sarif_report(scan_result, args.sarif_out)
    if args.write_baseline:
        if getattr(scan_result, "scan_trust_level", None) == "untrusted":
            # An untrusted scan produced zero findings from a fatal error; writing
            # that as the baseline would silently erase a real baseline and make
            # every later gated run flag everything as new. Skip the overwrite.
            print(
                f"Baseline not written ({args.write_baseline}): scan was untrusted; "
                "refusing to overwrite with an empty findings set.",
                file=sys.stderr,
            )
        else:
            reports["baseline"] = write_baseline(scan_result, args.write_baseline)
    return scan_result, reports


def _scan_kwargs(args) -> dict[str, object]:
    max_commits = args.history_max_commits if args.history_max_commits and args.history_max_commits > 0 else None
    return {
        "scan_history": bool(args.scan_history or args.history_only),
        "history_only": bool(args.history_only),
        "history_max_commits": max_commits,
        "history_since": args.history_since,
        "diff_mode": bool(args.diff),
        "diff_base": args.base,
        "diff_staged": bool(args.diff_staged),
        "enrich_owners": not bool(args.no_owner_enrich),
    }


def scan_with_reports(engine: Engine, project_path: str | Path, args) -> tuple[object, dict[str, Path]]:
    scan_result = engine.run_scan(project_path, baseline_path=args.baseline, **_scan_kwargs(args))
    return _post_process(scan_result, args)


def scan_with_json_report(engine: Engine, project_path: str | Path, args) -> tuple[object, Path]:
    scan_result = engine.run_scan(project_path, baseline_path=args.baseline, **_scan_kwargs(args))
    if args.write_baseline and getattr(scan_result, "scan_trust_level", None) != "untrusted":
        write_baseline(scan_result, args.write_baseline)
    if args.sarif_out:
        generate_sarif_report(scan_result, args.sarif_out)
    report_path = generate_json_report(scan_result, args.out)
    return scan_result, report_path


def host_audit_with_reports(engine: Engine, args) -> tuple[object, dict[str, Path]]:
    scan_result = engine.run_host_audit(
        args.host_root,
        baseline_path=args.baseline,
        no_elf_strings=bool(args.no_elf_strings),
    )
    return _post_process(scan_result, args)


EXIT_CLEAN = 0
EXIT_LOW_MEDIUM = 1
EXIT_HIGH_CRITICAL = 2
EXIT_CONFIG_ERROR = 3
EXIT_UNTRUSTED = 10


def severity_exit_code(scan_result) -> int:
    """Tiered exit code following the ESLint/Gitleaks convention."""
    if scan_result.scan_trust_level == "untrusted":
        return EXIT_UNTRUSTED
    new_severities = {
        finding.severity
        for finding in scan_result.findings
        if finding.baseline_status != "known"
    }
    if {"critical", "high"} & new_severities:
        return EXIT_HIGH_CRITICAL
    if {"medium", "low"} & new_severities:
        return EXIT_LOW_MEDIUM
    return EXIT_CLEAN


def exit_code_for_baseline(scan_result, args) -> int:
    if scan_result.scan_trust_level == "untrusted" and (
        getattr(args, "fail_on_new", None) or getattr(args, "severity_exit_codes", False)
    ):
        # Fail closed: a scan the engine itself marked untrusted (fatal errors,
        # zero findings) must not let gated invocations (pre-commit/CI) pass.
        return EXIT_UNTRUSTED
    if getattr(args, "severity_exit_codes", False):
        return severity_exit_code(scan_result)
    return 1 if has_new_findings_at_or_above(scan_result, args.fail_on_new) else 0


def _maybe_trend(engine: Engine, result, args):
    if not getattr(args, "trend", False):
        return None
    if engine.storage is None:
        return None
    from greynoc_nhi.trend import compute_trend
    try:
        return compute_trend(engine.storage, result)
    except Exception as exc:
        # Trend is best-effort reporting; never let it discard a completed
        # scan's summary and exit code. Emit to stderr so --json stdout stays a
        # clean machine-readable payload.
        print(f"Trend unavailable: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        try:
            from greynoc_nhi.gui import launch_gui
        except ImportError as exc:
            print(f"GUI requires Tkinter, which is not available: {exc}")
            print("Install your platform's Tk package (e.g. python3-tk) or use the CLI.")
            return 2
        launch_gui()
        return 0
    if args.clear_db:
        clear_all(args.db)
        print("Local GreyNOC NHI database cleared.")
        return 0
    if args.install_hook is not None:
        from greynoc_nhi.hooks import install_pre_commit_hook
        try:
            outcome = install_pre_commit_hook(
                args.install_hook,
                framework=bool(args.install_hook_framework),
                force=bool(args.install_hook_force),
            )
        except RuntimeError as exc:
            print(f"Hook install failed: {exc}")
            return 2
        print(f"Installed pre-commit hook at {outcome.hook_path}")
        if outcome.chained_existing:
            print("Existing pre-commit hook preserved as pre-commit.greynoc-chained")
        if outcome.overwrote:
            print("Reinstalled GreyNOC pre-commit hook")
        if outcome.framework_path:
            print(f"Wrote pre-commit framework manifest: {outcome.framework_path}")
        return 0
    if args.uninstall_hook is not None:
        from greynoc_nhi.hooks import uninstall_pre_commit_hook
        try:
            removed = uninstall_pre_commit_hook(args.uninstall_hook)
        except RuntimeError as exc:
            print(f"Hook removal failed: {exc}")
            return 2
        print("Hook removed." if removed else "No GreyNOC NHI hook installed; nothing to remove.")
        return 0
    if args.fix_gitignore is not None or args.fix_pin_actions is not None:
        from greynoc_nhi.autofix import fix_gitignore, fix_pin_actions
        results = []
        dry_run = bool(args.suggest_fix)
        if args.fix_gitignore is not None:
            results.append(fix_gitignore(args.fix_gitignore, dry_run=dry_run))
        if args.fix_pin_actions is not None:
            results.append(fix_pin_actions(args.fix_pin_actions, dry_run=dry_run))
        for outcome in results:
            print(outcome.summary())
            for note in outcome.notes:
                print(f"  - {note}")
        return 0
    wants_scan = bool(
        args.host_audit
        or args.linux_auth_audit
        or args.load_samples
        or args.scan
        or args.json_path
        or args.clear_cache
    )
    if not wants_scan:
        # No scan-triggering flag: print help without creating the scan DB or
        # parser cache as a side effect.
        build_parser().print_help()
        return 1
    if args.baseline:
        try:
            read_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"Baseline config error ({args.baseline}): {exc}")
            return EXIT_CONFIG_ERROR
    if args.rules:
        # A typo'd or malformed rule pack must fail closed: silently scanning
        # with zero custom rules would let a gated CI/pre-commit run pass while
        # missing exactly the findings the pack was configured to catch.
        try:
            raw = Path(args.rules).read_text(encoding="utf-8")
            parsed = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"Rule pack config error ({args.rules}): {exc}")
            return EXIT_CONFIG_ERROR
        if not isinstance(parsed, dict) or not isinstance(parsed.get("rules"), list) or not parsed.get("rules"):
            print(f"Rule pack config error ({args.rules}): no 'rules' list found")
            return EXIT_CONFIG_ERROR
        # Shape alone is not enough: load_rule_pack silently drops rules with an
        # uncompilable pattern, bad severity, or missing id. If the pack declared
        # rules but none load, fail closed so a gated run cannot pass while
        # silently scanning with zero custom rules.
        from greynoc_nhi.custom_rules import load_rule_pack
        if not load_rule_pack(args.rules):
            print(f"Rule pack config error ({args.rules}): no valid rules loaded (check patterns, ids, severities)")
            return EXIT_CONFIG_ERROR
    engine = Engine(args.db, rule_pack_path=args.rules, cache_enabled=not args.no_cache)
    if args.clear_cache and engine.cache is not None:
        engine.cache.clear()
    if args.host_audit or args.linux_auth_audit:
        result, reports = with_cli_indicator(
            "Auditing Linux PAM/SSH host auth",
            lambda: host_audit_with_reports(engine, args),
        )
        trend = _maybe_trend(engine, result, args)
        print_summary(result, reports, trend=trend)
        return exit_code_for_baseline(result, args)
    if args.load_samples:
        result, reports = with_cli_indicator(
            "Scanning sample project",
            lambda: scan_with_reports(engine, sample_project_path(), args),
        )
        trend = _maybe_trend(engine, result, args)
        print_summary(result, reports, trend=trend)
        return exit_code_for_baseline(result, args)
    if args.scan:
        result, reports = with_cli_indicator(
            "Scanning project",
            lambda: scan_with_reports(engine, args.scan, args),
        )
        trend = _maybe_trend(engine, result, args)
        print_summary(result, reports, trend=trend)
        return exit_code_for_baseline(result, args)
    if args.json_path:
        result, report_path = with_cli_indicator(
            "Scanning project",
            lambda: scan_with_json_report(engine, args.json_path, args),
        )
        trend = _maybe_trend(engine, result, args)
        payload = {"scan": result.to_dict(), "json_report": str(report_path)}
        if trend is not None:
            payload["trend"] = trend.to_dict()
        print(json.dumps(payload, indent=2))
        return exit_code_for_baseline(result, args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
