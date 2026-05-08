"""Tkinter GUI for GreyNOC NHI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from greynoc_nhi.constants import DEFAULT_REPORTS_DIR, FIRST_RUN_FLAG_PATH
from greynoc_nhi.engine import Engine
from greynoc_nhi.reports import generate_html_report, generate_json_report, generate_markdown_report
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.scoring import severity_label


def open_path_in_file_manager(path: str | Path) -> bool:
    """Open `path` in the platform-native file manager. Returns True on success."""
    target = str(Path(path))
    if sys.platform.startswith("win"):
        try:
            os.startfile(target)  # type: ignore[attr-defined]
            return True
        except (AttributeError, OSError):
            return False
    if sys.platform == "darwin":
        opener = shutil.which("open")
        if not opener:
            return False
        try:
            subprocess.Popen([opener, target])
            return True
        except OSError:
            return False
    opener = shutil.which("xdg-open") or shutil.which("gio")
    if not opener:
        return False
    try:
        if opener.endswith("gio"):
            subprocess.Popen([opener, "open", target])
        else:
            subprocess.Popen([opener, target])
        return True
    except OSError:
        return False


class PixelClusterIndicator(tk.Canvas):
    """Small animated pixel cluster used while a scan is active."""

    _frames = (
        ((0, 2, "#18b985"), (1, 1, "#7dd3fc"), (2, 2, "#d7f9ef"), (3, 1, "#0d6e7d")),
        ((0, 1, "#7dd3fc"), (1, 2, "#18b985"), (2, 1, "#d7f9ef"), (3, 2, "#18b985")),
        ((0, 2, "#d7f9ef"), (1, 1, "#0d6e7d"), (2, 2, "#18b985"), (3, 1, "#7dd3fc")),
        ((0, 1, "#18b985"), (1, 2, "#d7f9ef"), (2, 1, "#7dd3fc"), (3, 2, "#0d6e7d")),
    )

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, width=92, height=28, bg="#f0f4f6", highlightthickness=0)
        self._frame_index = 0
        self._running = False
        self._after_id: str | None = None
        self._draw_idle()

    def start(self) -> None:
        self._running = True
        self._tick()

    def stop(self) -> None:
        self._running = False
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None
        self._draw_idle()

    def _draw_idle(self) -> None:
        self.delete("all")
        for idx, color in enumerate(["#9fb5bc", "#7f9aa3", "#9fb5bc", "#c6d5d9"]):
            self._pixel(18 + idx * 14, 12, color)

    def _tick(self) -> None:
        if not self._running:
            return
        self.delete("all")
        for column, row, color in self._frames[self._frame_index]:
            self._pixel(18 + column * 14, 6 + row * 6, color)
        self._frame_index = (self._frame_index + 1) % len(self._frames)
        self._after_id = self.after(120, self._tick)

    def _pixel(self, x: int, y: int, color: str) -> None:
        size = 8
        self.create_rectangle(x, y, x + size, y + size, fill=color, outline=color)


class GreyNOCApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("GreyNOC Non-Human Identity Risk Engine")
        self.geometry("1180x760")
        self.project_path = tk.StringVar(value="")
        self.status = tk.StringVar(value="Select a project folder or load the bundled sample project.")
        self.engine = Engine()
        self.result = None
        self._build()
        self.after(350, self.show_first_run_help)

    def _build(self) -> None:
        header = tk.Frame(self, bg="#071317", padx=18, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="GreyNOC Non-Human Identity Risk Engine", bg="#071317", fg="white", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(header, text="Developer-first NHI, secret, OAuth, CI/CD, and AI-agent risk scanner", bg="#071317", fg="#b9d8dd", font=("Segoe UI", 10)).pack(anchor="w")

        cards = tk.Frame(self, padx=12, pady=10)
        cards.pack(fill="x")
        self.card_vars = {name: tk.StringVar(value="0") for name in ["Overall Risk", "Identities Found", "Critical Findings", "Advanced Correlations"]}
        for label, var in self.card_vars.items():
            frame = ttk.LabelFrame(cards, text=label)
            frame.pack(side="left", fill="x", expand=True, padx=5)
            ttk.Label(frame, textvariable=var, font=("Segoe UI", 18, "bold")).pack(padx=10, pady=10)

        controls = tk.Frame(self, padx=12)
        controls.pack(fill="x")
        ttk.Entry(controls, textvariable=self.project_path).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(
            controls,
            text="Start",
            command=self.select_project,
            bg="#c1121f",
            fg="white",
            activebackground="#8f0d17",
            activeforeground="white",
            font=("Segoe UI", 14, "bold"),
            padx=28,
            pady=8,
            relief="flat",
            cursor="hand2",
        ).pack(side="left", padx=5)
        ttk.Button(controls, text="Load Sample Project", command=self.load_sample).pack(side="left", padx=3)
        ttk.Button(controls, text="Clear Results", command=self.clear_results).pack(side="left", padx=3)

        actions = tk.Frame(self, padx=12, pady=8)
        actions.pack(fill="x")
        ttk.Button(actions, text="Run Analysis", command=self.run_analysis).pack(side="left", padx=3)
        ttk.Button(actions, text="Export HTML Report", command=lambda: self.export("html")).pack(side="left", padx=3)
        ttk.Button(actions, text="Export JSON Report", command=lambda: self.export("json")).pack(side="left", padx=3)
        ttk.Button(actions, text="Export Markdown Report", command=lambda: self.export("md")).pack(side="left", padx=3)
        ttk.Button(actions, text="Open Reports Folder", command=self.open_reports_folder).pack(side="left", padx=3)
        self.indicator = PixelClusterIndicator(actions)
        self.indicator.pack(side="left", padx=(12, 2))
        ttk.Label(actions, textvariable=self.status).pack(side="left", padx=12)

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=8)
        self.summary_text = self._text_tab("Summary")
        self.findings_tree = self._tree_tab("Findings", ["Severity", "Score", "Rule", "Identity", "Source", "File", "Line", "Finding"])
        self.inventory_tree = self._tree_tab("Identity Inventory", ["Type", "Name", "Source", "Provider", "Environment", "Owner", "Permissions/Scopes/Tools", "Risk"])
        self.owasp_text = self._text_tab("OWASP Mapping")
        self.plan_text = self._text_tab("Remediation Plan")
        self.raw_text = self._text_tab("Raw JSON")

    def _text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.tabs)
        text = tk.Text(frame, wrap="word")
        text.pack(fill="both", expand=True)
        self.tabs.add(frame, text=title)
        return text

    def _tree_tab(self, title: str, columns: list[str]) -> ttk.Treeview:
        frame = ttk.Frame(self.tabs)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=130, anchor="w")
        tree.pack(fill="both", expand=True)
        self.tabs.add(frame, text=title)
        return tree

    def select_project(self) -> None:
        selected = filedialog.askdirectory()
        if selected:
            self.project_path.set(selected)

    def load_sample(self) -> None:
        self.project_path.set(str(sample_project_path()))
        self.status.set("Sample project loaded.")

    def clear_results(self) -> None:
        self.result = None
        for var in self.card_vars.values():
            var.set("0")
        for widget in [self.summary_text, self.owasp_text, self.plan_text, self.raw_text]:
            widget.delete("1.0", "end")
        for tree in [self.findings_tree, self.inventory_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.status.set("Results cleared.")

    def run_analysis(self) -> None:
        project = self.project_path.get()
        if not project:
            messagebox.showwarning("Project required", "Select a project folder first.")
            return
        self.status.set("Scanning locally...")
        self.indicator.start()
        threading.Thread(target=self._scan_worker, args=(project,), daemon=True).start()

    def _scan_worker(self, project: str) -> None:
        try:
            result = self.engine.run_scan(project)
            self.after(0, lambda: self._render_result(result))
        except Exception as exc:
            self.after(0, lambda: self._scan_failed(str(exc)))

    def _scan_failed(self, message: str) -> None:
        self.indicator.stop()
        self.status.set("Scan failed.")
        messagebox.showerror("Scan failed", message)

    def _render_result(self, result) -> None:
        self.result = result
        self.indicator.stop()
        self.card_vars["Overall Risk"].set(f"{result.overall_score} ({severity_label(result.overall_score)})")
        self.card_vars["Identities Found"].set(str(len(result.identities)))
        self.card_vars["Critical Findings"].set(str(sum(1 for f in result.findings if f.severity == "critical")))
        self.card_vars["Advanced Correlations"].set(str(result.stats.get("advanced_correlations", 0)))
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("end", result.summary)
        for tree in [self.findings_tree, self.inventory_tree]:
            for item in tree.get_children():
                tree.delete(item)
        for f in result.findings:
            self.findings_tree.insert("", "end", values=(f.severity, f.risk_score, f.rule_id, f.identity_name or "-", f.source, f.file_path or "-", f.line_number or "-", f.title))
        for i in result.identities:
            self.inventory_tree.insert("", "end", values=(i.identity_type, i.name, i.source, i.provider or "-", i.environment or "-", i.owner or "-", ", ".join(i.permissions + i.scopes + i.tools), ", ".join(i.tags)))
        counts: dict[str, int] = {}
        for f in result.findings:
            for ref in f.owasp_nhi_refs:
                counts[ref] = counts.get(ref, 0) + 1
        self.owasp_text.delete("1.0", "end")
        self.owasp_text.insert("end", "\n".join(f"{ref}: {count}" for ref, count in sorted(counts.items())) or "No mapped findings.")
        self.plan_text.delete("1.0", "end")
        self.plan_text.insert("end", "Day 0-3: critical cleanup\nDay 4-10: rotate/revoke/re-scope\nDay 11-20: CI/CD and cloud hardening\nDay 21-30: owners, logging, approval gates")
        self.raw_text.delete("1.0", "end")
        self.raw_text.insert("end", json.dumps(result.to_dict(), indent=2))
        self.status.set("Scan completed.")

    def export(self, report_type: str) -> None:
        if not self.result:
            messagebox.showwarning("No result", "Run an analysis first.")
            return
        out = filedialog.askdirectory(initialdir=str(DEFAULT_REPORTS_DIR)) or str(DEFAULT_REPORTS_DIR)
        if report_type == "html":
            path = generate_html_report(self.result, out)
        elif report_type == "json":
            path = generate_json_report(self.result, out)
        else:
            path = generate_markdown_report(self.result, out)
        self.status.set(f"Report exported: {path}")

    def open_reports_folder(self) -> None:
        DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            opened = open_path_in_file_manager(DEFAULT_REPORTS_DIR)
        except OSError as exc:
            messagebox.showinfo("Reports folder", f"{DEFAULT_REPORTS_DIR}\n\n({exc})")
            return
        if not opened:
            messagebox.showinfo("Reports folder", str(DEFAULT_REPORTS_DIR))

    def show_first_run_help(self) -> None:
        if FIRST_RUN_FLAG_PATH.exists():
            return
        messagebox.showinfo(
            "Welcome to GreyNOC NHI",
            "How to use this app:\n\n"
            "1. Click Start and choose the project folder you want to assess.\n"
            "2. Click Run Analysis.\n"
            "3. Review Summary, Findings, Identity Inventory, OWASP Mapping, and Remediation Plan.\n"
            "4. Export HTML, JSON, or Markdown reports when you are ready.\n\n"
            "GreyNOC runs locally, masks secrets, and does not validate or use credentials.",
        )
        FIRST_RUN_FLAG_PATH.parent.mkdir(parents=True, exist_ok=True)
        FIRST_RUN_FLAG_PATH.write_text("seen\n", encoding="utf-8")


def launch_gui() -> None:
    app = GreyNOCApp()
    app.mainloop()
