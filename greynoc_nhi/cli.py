"""Command-line interface for GreyNOC NHI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from greynoc_nhi.constants import DEFAULT_DB_PATH
from greynoc_nhi.engine import Engine
from greynoc_nhi.gui import launch_gui
from greynoc_nhi.indicators import with_cli_indicator
from greynoc_nhi.reports import generate_all_reports, generate_json_report
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
    return parser


def print_summary(result, reports: dict[str, Path] | None = None) -> None:
    print("Scan completed")
    print(f"Overall score: {result.overall_score}")
    print(f"Severity label: {severity_label(result.overall_score)}")
    print(f"Identities found: {len(result.identities)}")
    print(f"Findings count: {len(result.findings)}")
    print(f"Advanced correlations: {result.stats.get('advanced_correlations', 0)}")
    if reports:
        for report_type, path in reports.items():
            print(f"{report_type.upper()} report: {path}")


def scan_with_reports(engine: Engine, project_path: str | Path, out_dir: str | None) -> tuple[object, dict[str, Path]]:
    scan_result = engine.run_scan(project_path)
    return scan_result, generate_all_reports(scan_result, out_dir)


def scan_with_json_report(engine: Engine, project_path: str | Path, out_dir: str | None) -> tuple[object, Path]:
    scan_result = engine.run_scan(project_path)
    return scan_result, generate_json_report(scan_result, out_dir)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        launch_gui()
        return 0
    if args.clear_db:
        clear_all(args.db)
        print("Local GreyNOC NHI database cleared.")
        return 0
    engine = Engine(args.db)
    if args.load_samples:
        result, reports = with_cli_indicator(
            "Scanning sample project",
            lambda: scan_with_reports(engine, sample_project_path(), args.out),
        )
        print_summary(result, reports)
        return 0
    if args.scan:
        result, reports = with_cli_indicator(
            "Scanning project",
            lambda: scan_with_reports(engine, args.scan, args.out),
        )
        print_summary(result, reports)
        return 0
    if args.json_path:
        result, report_path = with_cli_indicator(
            "Scanning project",
            lambda: scan_with_json_report(engine, args.json_path, args.out),
        )
        print(json.dumps({"scan": result.to_dict(), "json_report": str(report_path)}, indent=2))
        return 0
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
