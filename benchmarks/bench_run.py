"""Benchmark runner: times the scanner and scores detection recall/FPs.

Usage: python bench_run.py <corpus_root> [label]
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from greynoc_nhi.engine import Engine  # noqa: E402
from greynoc_nhi.scanner import iter_scan_files  # noqa: E402


def time_it(fn, repeats: int = 3):
    times = []
    result = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = fn()
        times.append(time.perf_counter() - t0)
    return min(times), statistics.median(times), result


def main() -> None:
    corpus = Path(sys.argv[1])
    label = sys.argv[2] if len(sys.argv) > 2 else "run"
    perf_repo = corpus / "perf_repo"
    detect_repo = corpus / "detect_repo"

    out: dict = {"label": label}

    # 1. traversal only
    tmin, tmed, files = time_it(lambda: iter_scan_files(perf_repo), repeats=3)
    out["traversal_s"] = round(tmin, 3)
    out["traversal_files"] = len(files)

    # 2. full scan, no persistence, no cache
    engine = Engine(db_path=None, cache_enabled=False)
    smin, smed, res = time_it(lambda: engine.run_scan(perf_repo, persist=False, enrich_owners=False), repeats=3)
    out["full_scan_s"] = round(smin, 3)
    out["scanned_files"] = res.stats.get("scanned_files") if hasattr(res, "stats") else None
    try:
        out["findings"] = len(res.findings)
        out["identities"] = len(res.identities)
    except Exception:
        pass

    # 3. detection scorecard
    det_engine = Engine(db_path=None, cache_enabled=False)
    dres = det_engine.run_scan(detect_repo, persist=False, enrich_owners=False)

    planted_ids = {p.name for p in (detect_repo / "planted").iterdir() if p.is_dir()}
    placebo_ids = {p.name for p in (detect_repo / "placebo").iterdir() if p.is_dir()}

    def bucket_of(path_str: str) -> tuple[str, str] | None:
        norm = path_str.replace("\\", "/")
        for kind, ids in (("planted", planted_ids), ("placebo", placebo_ids)):
            marker = f"/{kind}/"
            if marker in norm:
                rest = norm.split(marker, 1)[1]
                return kind, rest.split("/", 1)[0]
        return None

    hit_planted: set[str] = set()
    fp_placebo: dict[str, int] = {}
    secretish = 0
    for f in dres.findings:
        fpath = getattr(f, "file_path", None) or getattr(f, "source_file", "") or ""
        if not fpath:
            ident = getattr(f, "identity", None)
            fpath = getattr(ident, "source_file", "") if ident else ""
        b = bucket_of(str(fpath))
        if b is None:
            continue
        kind, pid = b
        if kind == "planted":
            hit_planted.add(pid)
        else:
            fp_placebo[pid] = fp_placebo.get(pid, 0) + 1
        secretish += 1

    # fall back to identities when findings lack paths
    for ident in dres.identities:
        b = bucket_of(str(getattr(ident, "source_file", "") or ""))
        if b and b[0] == "planted":
            pass  # identities alone don't count as detection hits; findings do

    missed = sorted(planted_ids - hit_planted)
    out["recall"] = f"{len(hit_planted)}/{len(planted_ids)}"
    out["recall_pct"] = round(100 * len(hit_planted) / max(1, len(planted_ids)), 1)
    out["missed_planted"] = missed
    out["placebo_fp_dirs"] = sorted(fp_placebo)
    out["placebo_fp_count"] = sum(fp_placebo.values())

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
