"""
report.py — NullTracer Phase 4 Validation Report Generator
===========================================================
Runs the full validation suite programmatically (detection tests + overhead
benchmark) and renders a consolidated Rich terminal report with pass/fail
status, rate metrics, overhead stats, and an Invoke-AtomicRedTeam guide for
live VM testing.

Usage:
    python -m validation.report
    python -m validation.report --events 20000 --json results/report.json
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.rule    import Rule
from rich         import box
from rich.text    import Text

# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from validation.metrics   import (
    run_engine_on_fixture, DetectionResult, DetectionRates,
    OverheadReport,
)
from validation.benchmark import _make_event_stream, _run_once

console = Console(force_terminal=True, highlight=False)

_RULES_DIR = _PROJECT_ROOT / "samples" / "rules"
_TELEMETRY = _PROJECT_ROOT / "samples" / "telemetry"

# ---------------------------------------------------------------------------
# Detection suite runner (mirrors test_detection.py logic)
# ---------------------------------------------------------------------------

_FIXTURE_DEFS = [
    # (path,                               expected_alerts, label)
    ("atomic_lolbin_tp.json",               1,  "Atomic LOLbin TP (T1059.001->T1218.011->T1047)"),
    ("synthetic_events.json",               1,  "Synthetic dev fixture (regression)"),
    ("etw_kernel_join.json",                1,  "ETW script block correlation"),
    ("benign_noise.json",                   0,  "Benign system noise (FP guard)"),
    ("partial_chains.json",                 0,  "Partial / broken chains (FP guard)"),
]


def _run_detection_suite() -> DetectionRates:
    results: List[DetectionResult] = []
    for fname, expected, label in _FIXTURE_DEFS:
        path = _TELEMETRY / fname
        if not path.exists():
            console.print(f"  [yellow]⚠[/yellow]  Fixture not found, skipping: {fname}")
            continue
        alerts = run_engine_on_fixture(path, _RULES_DIR)
        r = DetectionResult(
            fixture_path    = str(path),
            expected_alerts = expected,
            actual_alerts   = len(alerts),
            alert_messages  = alerts,
        )
        results.append(r)
    return DetectionRates(results=results)


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------

def _status_icon(ok: bool) -> str:
    return "[bold green]PASS[/bold green]" if ok else "[bold red]FAIL[/bold red]"


def _render_detection_table(rates: DetectionRates) -> None:
    tbl = Table(
        title="Detection Accuracy — Fixture Results",
        box=box.ROUNDED, border_style="bright_black", expand=True,
    )
    tbl.add_column("Fixture",         style="dim", no_wrap=False)
    tbl.add_column("Expected Alerts", justify="center")
    tbl.add_column("Actual Alerts",   justify="center")
    tbl.add_column("Category",        justify="center")
    tbl.add_column("Result",          justify="center")

    for fname, expected, label in _FIXTURE_DEFS:
        path = _TELEMETRY / fname
        if not path.exists():
            continue
        # Find matching result
        r = next((x for x in rates.results if x.fixture_path.endswith(fname)), None)
        if r is None:
            continue

        if r.is_true_positive:
            cat    = "[green]True Positive[/green]"
            status = _status_icon(True)
        elif r.is_true_negative:
            cat    = "[green]True Negative[/green]"
            status = _status_icon(True)
        elif r.is_false_positive:
            cat    = "[red]FALSE POSITIVE[/red]"
            status = _status_icon(False)
        else:
            cat    = "[red]FALSE NEGATIVE[/red]"
            status = _status_icon(False)

        tbl.add_row(label, str(expected), str(r.actual_alerts), cat, status)

    console.print(tbl)


def _render_rate_panel(rates: DetectionRates) -> None:
    dr   = rates.detection_rate
    fpr  = rates.false_positive_rate
    prec = rates.precision
    f1   = rates.f1

    def _pct(v: float) -> str:
        color = "green" if v >= 0.99 else ("yellow" if v >= 0.8 else "red")
        return f"[bold {color}]{v:.1%}[/bold {color}]"

    def _fpr_pct(v: float) -> str:
        color = "green" if v == 0.0 else ("yellow" if v <= 0.1 else "red")
        return f"[bold {color}]{v:.1%}[/bold {color}]"

    lines = [
        f"  Detection Rate (TPR)   : {_pct(dr)}   [dim](TP={rates.tp}, FN={rates.fn})[/dim]",
        f"  False Positive Rate    : {_fpr_pct(fpr)}   [dim](FP={rates.fp}, TN={rates.tn})[/dim]",
        f"  Precision              : {_pct(prec)}",
        f"  F1 Score               : {_pct(f1)}",
    ]
    console.print(Panel(
        "\n".join(lines),
        title="[bold]Aggregate Rates[/bold]",
        border_style="cyan",
    ))


def _render_overhead(report: OverheadReport, event_count: int) -> None:
    s = report.summary()
    if not s:
        return
    total_elapsed = s["total_elapsed_s"]
    avg_eps = s["total_events"] / total_elapsed if total_elapsed else 0

    lines = [
        f"  Events processed  : [bold]{s['total_events']:,}[/bold] ({event_count:,} × {s['total_events'] // event_count} runs)",
        f"  Throughput        : [bold green]{avg_eps:,.0f} events/s[/bold green]",
        f"  Avg CPU           : [bold]{s['avg_cpu_pct']:.1f}%[/bold]   Peak: {s['max_cpu_pct']:.1f}%",
        f"  Avg RSS           : [bold]{s['avg_rss_mb']:.1f} MiB[/bold]  Peak: {s['max_rss_mb']:.1f} MiB",
        f"  Total wall time   : [bold]{total_elapsed:.3f} s[/bold]",
    ]
    console.print(Panel(
        "\n".join(lines),
        title="[bold]CPU / Memory Overhead[/bold]",
        border_style="magenta",
    ))


def _render_atomic_guide() -> None:
    guide = """[bold]Live VM Validation (Invoke-AtomicRedTeam)[/bold]

Run the following on a [bold yellow]test VM[/bold yellow] with NullTracerDrv.sys loaded
and [cyan]python -m agent.nulltracer_agent[/cyan] running in a separate terminal:

  [dim]# 1. Install Invoke-AtomicRedTeam (PowerShell, run as Admin)[/dim]
  [cyan]Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force[/cyan]
  [cyan]Install-Module -Name powershell-yaml      -Scope CurrentUser -Force[/cyan]
  [cyan]IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics[/cyan]

  [dim]# 2. Run the three LOLbin techniques in sequence[/dim]
  [cyan]Invoke-AtomicTest T1059.001 -TestNumbers 1   # PowerShell encoded cmd[/cyan]
  [cyan]Invoke-AtomicTest T1218.011 -TestNumbers 1   # RunDLL32 unusual DLL[/cyan]
  [cyan]Invoke-AtomicTest T1047     -TestNumbers 1   # WMI lateral execution[/cyan]

  [dim]# 3. Expected agent output (within ~200 ms of last technique):[/dim]
  [green][ALERT] LOLbin Lateral Movement detected! MITRE: T1059.001, T1218.011, T1047.[/green]

  [dim]# 4. Verify ring buffer stats[/dim]
  [cyan]python -m agent.nulltracer_agent --stats[/cyan]

  [dim]# 5. Cleanup atomic leftovers[/dim]
  [cyan]Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup[/cyan]
  [cyan]Invoke-AtomicTest T1218.011 -TestNumbers 1 -Cleanup[/cyan]
  [cyan]Invoke-AtomicTest T1047     -TestNumbers 1 -Cleanup[/cyan]"""

    console.print(Panel(guide, border_style="yellow", expand=True))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="NullTracer Phase 4 — Full Validation Report"
    )
    parser.add_argument(
        "--events", type=int, default=10_000,
        help="Events for overhead benchmark (default: 10,000)",
    )
    parser.add_argument(
        "--benchmark-repeats", type=int, default=3,
        help="Benchmark repetitions (default: 3)",
    )
    parser.add_argument(
        "--json", type=Path, default=None,
        metavar="OUTPUT",
        help="Save full report JSON to this path",
    )
    parser.add_argument(
        "--no-benchmark", action="store_true",
        help="Skip the overhead benchmark (detection tests only)",
    )
    args = parser.parse_args(argv)

    ts = datetime.now(tz=timezone.utc).isoformat()

    console.print()
    console.print(Rule("[bold cyan]NullTracer Phase 4 Validation Report[/bold cyan]"))
    console.print(f"  [dim]Generated: {ts}[/dim]")
    console.print(f"  [dim]Rules dir: {_RULES_DIR}[/dim]")
    console.print()

    # ---------------------------------------------------------------- #
    # Section 1 — Detection accuracy                                   #
    # ---------------------------------------------------------------- #
    console.print(Rule("[bold]§1  Detection Accuracy[/bold]"))
    console.print()
    console.print("  Running fixtures through CorrelationEngine…")
    rates = _run_detection_suite()
    console.print()
    _render_detection_table(rates)
    console.print()
    _render_rate_panel(rates)
    console.print()

    # ---------------------------------------------------------------- #
    # Section 2 — Overhead benchmark                                   #
    # ---------------------------------------------------------------- #
    if not args.no_benchmark:
        console.print(Rule("[bold]§2  CPU / Memory Overhead Benchmark[/bold]"))
        console.print()
        console.print(f"  Generating [cyan]{args.events:,}[/cyan] synthetic events "
                      f"× {args.benchmark_repeats} repeats…")
        events = _make_event_stream(args.events)
        overhead_report = OverheadReport()
        for i in range(1, args.benchmark_repeats + 1):
            console.print(f"  [dim]Run {i}/{args.benchmark_repeats}…[/dim]", end="\r")
            sample = _run_once(events, _RULES_DIR, label=f"Run {i}")
            overhead_report.add(sample)
        console.print()
        _render_overhead(overhead_report, args.events)
        console.print()
    else:
        overhead_report = OverheadReport()

    # ---------------------------------------------------------------- #
    # Section 3 — Live VM guide                                        #
    # ---------------------------------------------------------------- #
    console.print(Rule("[bold]§3  Live VM Validation Guide (Invoke-AtomicRedTeam)[/bold]"))
    console.print()
    _render_atomic_guide()
    console.print()

    # ---------------------------------------------------------------- #
    # Overall verdict                                                  #
    # ---------------------------------------------------------------- #
    all_pass = (rates.detection_rate == 1.0 and rates.false_positive_rate == 0.0)
    verdict_color = "green" if all_pass else "red"
    verdict_text  = "ALL CHECKS PASSED" if all_pass else "SOME CHECKS FAILED"
    console.print(Panel(
        f"[bold {verdict_color}]{verdict_text}[/bold {verdict_color}]",
        border_style=verdict_color,
        expand=False,
    ))
    console.print()

    # ---------------------------------------------------------------- #
    # Optional JSON output                                             #
    # ---------------------------------------------------------------- #
    if args.json:
        data = {
            "generated_at": ts,
            "detection": {
                "tp": rates.tp, "fp": rates.fp, "fn": rates.fn, "tn": rates.tn,
                "detection_rate":    rates.detection_rate,
                "false_positive_rate": rates.false_positive_rate,
                "precision":         rates.precision,
                "f1":                rates.f1,
                "results": [
                    {
                        "fixture":          r.fixture_path,
                        "expected_alerts":  r.expected_alerts,
                        "actual_alerts":    r.actual_alerts,
                        "is_tp":            r.is_true_positive,
                        "is_fp":            r.is_false_positive,
                        "is_fn":            r.is_false_negative,
                        "is_tn":            r.is_true_negative,
                    }
                    for r in rates.results
                ],
            },
            "overhead": json.loads(overhead_report.to_json()) if overhead_report.samples else {},
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report saved → {args.json}[/dim]\n")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
