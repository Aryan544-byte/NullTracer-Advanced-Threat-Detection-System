"""
benchmark.py — NullTracer Phase 4 CPU/Memory Overhead Benchmark
================================================================
Measures the CPU and memory overhead of the CorrelationEngine by replaying
a synthetic event stream of configurable size, sampling resource usage via
psutil throughout the run, and printing a Rich formatted report.

Usage:
    python -m validation.benchmark
    python -m validation.benchmark --events 50000 --repeats 5
    python -m validation.benchmark --json results/overhead.json

The benchmark does NOT require the kernel driver to be loaded — it runs the
same replay path used by the test suite.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path
from typing import List

import psutil
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from validation.metrics import OverheadReport, OverheadSample

console = Console(force_terminal=True, highlight=False)

# ---------------------------------------------------------------------------
# Synthetic event generator
# ---------------------------------------------------------------------------

def _make_event_stream(count: int) -> list:
    """
    Generate `count` synthetic ProcessCreate events.  Every 4th event is a
    complete LOLbin chain (triggering an alert); the rest are benign svchost
    noise.  This gives a realistic 25% "interesting" / 75% noise mix.
    """
    events = []
    base_ts = 1_700_000_000.0
    chain_pid_base = 10_000

    for i in range(count):
        ts = base_ts + i * 0.1

        if i % 4 == 0:
            # Benign explorer parent
            events.append({
                "timestamp": ts,
                "event_type": "ProcessCreate",
                "pid": chain_pid_base + i * 10,
                "ppid": 400,
                "image_path": "C:\\Windows\\System32\\explorer.exe",
                "command_line": "explorer.exe",
                "details": {}
            })
        elif i % 4 == 1:
            # powershell -enc (child of explorer above)
            events.append({
                "timestamp": ts,
                "event_type": "ProcessCreate",
                "pid": chain_pid_base + i * 10,
                "ppid": chain_pid_base + (i - 1) * 10,
                "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
                "details": {}
            })
        elif i % 4 == 2:
            # rundll32 (child of powershell)
            events.append({
                "timestamp": ts,
                "event_type": "ProcessCreate",
                "pid": chain_pid_base + i * 10,
                "ppid": chain_pid_base + (i - 1) * 10,
                "image_path": "C:\\Windows\\System32\\rundll32.exe",
                "command_line": "rundll32.exe C:\\Users\\Public\\p.dll,EP",
                "details": {}
            })
        else:
            # WmiPrvSE (child of rundll32) — completes the chain
            events.append({
                "timestamp": ts,
                "event_type": "ProcessCreate",
                "pid": chain_pid_base + i * 10,
                "ppid": chain_pid_base + (i - 1) * 10,
                "image_path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                "command_line": "WmiPrvSE.exe -secured -Embedding",
                "details": {}
            })

    return events


# ---------------------------------------------------------------------------
# CPU / memory sampler (runs on a background thread)
# ---------------------------------------------------------------------------

class _ResourceSampler:
    """Periodically samples psutil metrics on the current process."""

    INTERVAL = 0.25   # seconds between samples

    def __init__(self, proc: psutil.Process):
        self._proc    = proc
        self._stop    = threading.Event()
        self._samples: List[dict] = []
        self._thread  = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> List[dict]:
        self._stop.set()
        self._thread.join(timeout=2)
        return self._samples

    def _loop(self) -> None:
        # Warm up the cpu_percent call (first call always returns 0.0)
        self._proc.cpu_percent(interval=None)
        while not self._stop.is_set():
            try:
                cpu = self._proc.cpu_percent(interval=None)
                mem = self._proc.memory_info().rss / (1024 * 1024)  # MiB
                self._samples.append({"cpu": cpu, "mem": mem})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            self._stop.wait(self.INTERVAL)


# ---------------------------------------------------------------------------
# Single benchmark run
# ---------------------------------------------------------------------------

def _run_once(
    events:    list,
    rules_dir: Path,
    label:     str,
) -> OverheadSample:
    """Replay *events* through the engine and return resource usage."""
    from engine.models        import TelemetryEvent
    from engine.schema        import parse_chain_yaml
    from engine.state_machine import CorrelationEngine

    chains = [parse_chain_yaml(str(y)) for y in sorted(rules_dir.glob("*.yml"))]
    engine = CorrelationEngine(chains)

    proc    = psutil.Process()
    sampler = _ResourceSampler(proc)

    sampler.start()
    t0 = time.perf_counter()

    alert_count = 0
    for raw in events:
        ev = TelemetryEvent.from_dict(raw)
        alert_count += len(engine.ingest(ev))

    elapsed = time.perf_counter() - t0
    samples = sampler.stop()

    cpus = [s["cpu"] for s in samples] or [0.0]
    mems = [s["mem"] for s in samples] or [0.0]

    return OverheadSample(
        label        = label,
        cpu_percent  = sum(cpus) / len(cpus),
        rss_mb       = max(mems),
        elapsed_s    = elapsed,
        events_count = len(events),
    )


# ---------------------------------------------------------------------------
# Rich report
# ---------------------------------------------------------------------------

def _print_report(report: OverheadReport, event_count: int, repeats: int) -> None:
    summary = report.summary()

    console.print()
    console.print(Panel.fit(
        "[bold cyan]NullTracer Phase 4 — CPU/Memory Overhead Benchmark[/bold cyan]",
        border_style="cyan",
    ))

    # Per-run table
    tbl = Table(
        title=f"Per-Run Results  ({event_count:,} events × {repeats} repeats)",
        box=box.ROUNDED,
        border_style="bright_black",
        show_footer=False,
    )
    tbl.add_column("Run",          style="bold", justify="right")
    tbl.add_column("Events",       justify="right")
    tbl.add_column("Elapsed (s)",  justify="right")
    tbl.add_column("Events/s",     justify="right", style="green")
    tbl.add_column("Avg CPU %",    justify="right")
    tbl.add_column("Peak RSS MiB", justify="right")

    for s in report.samples:
        eps = s.events_count / s.elapsed_s if s.elapsed_s else 0
        tbl.add_row(
            s.label,
            f"{s.events_count:,}",
            f"{s.elapsed_s:.3f}",
            f"{eps:,.0f}",
            f"{s.cpu_percent:.1f}",
            f"{s.rss_mb:.1f}",
        )

    console.print(tbl)
    console.print()

    # Summary panel
    total_events = summary["total_events"]
    total_elapsed = summary["total_elapsed_s"]
    avg_eps = total_events / total_elapsed if total_elapsed else 0

    summary_lines = [
        f"  Total events processed : [bold]{total_events:,}[/bold]",
        f"  Total elapsed          : [bold]{total_elapsed:.3f} s[/bold]",
        f"  Average throughput     : [bold green]{avg_eps:,.0f} events/s[/bold green]",
        f"  Average CPU            : [bold]{summary['avg_cpu_pct']:.1f}%[/bold]",
        f"  Peak CPU               : [bold]{summary['max_cpu_pct']:.1f}%[/bold]",
        f"  Average RSS            : [bold]{summary['avg_rss_mb']:.1f} MiB[/bold]",
        f"  Peak RSS               : [bold]{summary['max_rss_mb']:.1f} MiB[/bold]",
    ]
    console.print(Panel(
        "\n".join(summary_lines),
        title="[bold]Summary[/bold]",
        border_style="green",
    ))
    console.print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="NullTracer Phase 4 CPU/Memory Overhead Benchmark",
    )
    parser.add_argument(
        "--events", type=int, default=10_000,
        help="Number of synthetic events per run (default: 10,000)",
    )
    parser.add_argument(
        "--repeats", type=int, default=3,
        help="Number of benchmark repetitions (default: 3)",
    )
    parser.add_argument(
        "--rules", type=Path,
        default=_PROJECT_ROOT / "samples" / "rules",
        help="Chain rules directory (default: samples/rules/)",
    )
    parser.add_argument(
        "--json", type=Path, default=None,
        metavar="OUTPUT",
        help="If set, write the raw JSON report to this path",
    )
    args = parser.parse_args(argv)

    console.print(f"\n[bold]Generating [cyan]{args.events:,}[/cyan] synthetic events...[/bold]")
    events = _make_event_stream(args.events)

    report = OverheadReport()

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Benchmarking…", total=args.repeats)
        for i in range(1, args.repeats + 1):
            sample = _run_once(events, args.rules, label=f"Run {i}")
            report.add(sample)
            prog.advance(task)

    _print_report(report, args.events, args.repeats)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report.to_json(), encoding="utf-8")
        console.print(f"[dim]JSON report saved to: {args.json}[/dim]\n")


if __name__ == "__main__":
    main()
