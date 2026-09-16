"""
metrics.py — NullTracer Phase 4 Validation Metrics
====================================================
Provides helper dataclasses and functions used by the test suite and the
benchmark runner to compute detection / false-positive rates and to record
CPU / memory overhead.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Detection result types
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Outcome of running one telemetry fixture through the engine."""
    fixture_path:    str
    expected_alerts: int          # alerts we expect (0 for benign/partial)
    actual_alerts:   int
    alert_messages:  List[str] = field(default_factory=list)

    @property
    def is_true_positive(self) -> bool:
        return self.expected_alerts > 0 and self.actual_alerts >= self.expected_alerts

    @property
    def is_false_negative(self) -> bool:
        return self.expected_alerts > 0 and self.actual_alerts < self.expected_alerts

    @property
    def is_false_positive(self) -> bool:
        return self.expected_alerts == 0 and self.actual_alerts > 0

    @property
    def is_true_negative(self) -> bool:
        return self.expected_alerts == 0 and self.actual_alerts == 0


@dataclass
class DetectionRates:
    """Aggregate detection / FP rates over a set of DetectionResults."""
    results:          List[DetectionResult]

    # --- computed lazily ---
    _tp: Optional[int] = field(default=None, repr=False, compare=False)
    _fp: Optional[int] = field(default=None, repr=False, compare=False)
    _fn: Optional[int] = field(default=None, repr=False, compare=False)
    _tn: Optional[int] = field(default=None, repr=False, compare=False)

    def _compute(self) -> None:
        if self._tp is not None:
            return
        self._tp = sum(1 for r in self.results if r.is_true_positive)
        self._fp = sum(1 for r in self.results if r.is_false_positive)
        self._fn = sum(1 for r in self.results if r.is_false_negative)
        self._tn = sum(1 for r in self.results if r.is_true_negative)

    @property
    def tp(self) -> int:
        self._compute(); return self._tp  # type: ignore

    @property
    def fp(self) -> int:
        self._compute(); return self._fp  # type: ignore

    @property
    def fn(self) -> int:
        self._compute(); return self._fn  # type: ignore

    @property
    def tn(self) -> int:
        self._compute(); return self._tn  # type: ignore

    @property
    def detection_rate(self) -> float:
        """True Positive Rate = TP / (TP + FN)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        """False Positive Rate = FP / (FP + TN)."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.detection_rate
        return 2 * p * r / (p + r) if (p + r) else 0.0


# ---------------------------------------------------------------------------
# Overhead measurement helpers
# ---------------------------------------------------------------------------

@dataclass
class OverheadSample:
    """One snapshot of process resource usage."""
    label:        str
    cpu_percent:  float     # % CPU averaged over interval_s
    rss_mb:       float     # Resident Set Size in MiB
    elapsed_s:    float     # wall-clock seconds the measurement took
    events_count: int       # how many events were processed during this window


@dataclass
class OverheadReport:
    """Collection of overhead samples with summary statistics."""
    samples: List[OverheadSample] = field(default_factory=list)

    def add(self, sample: OverheadSample) -> None:
        self.samples.append(sample)

    def summary(self) -> dict:
        if not self.samples:
            return {}
        cpus = [s.cpu_percent for s in self.samples]
        mems = [s.rss_mb      for s in self.samples]
        return {
            "avg_cpu_pct":  sum(cpus) / len(cpus),
            "max_cpu_pct":  max(cpus),
            "avg_rss_mb":   sum(mems) / len(mems),
            "max_rss_mb":   max(mems),
            "total_events": sum(s.events_count for s in self.samples),
            "total_elapsed_s": sum(s.elapsed_s for s in self.samples),
        }

    def to_json(self) -> str:
        data = {
            "samples": [
                {
                    "label":        s.label,
                    "cpu_percent":  s.cpu_percent,
                    "rss_mb":       s.rss_mb,
                    "elapsed_s":    s.elapsed_s,
                    "events_count": s.events_count,
                }
                for s in self.samples
            ],
            "summary": self.summary(),
        }
        return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Engine runner helper
# ---------------------------------------------------------------------------

def run_engine_on_fixture(
    fixture_path: Path,
    rules_dir:    Path,
) -> List[str]:
    """
    Load events from *fixture_path*, run them through the CorrelationEngine
    (using chain rules from *rules_dir*), and return all alert strings.

    This helper is the single point of truth for how the test suite and the
    benchmark both invoke the engine — keeping results comparable.
    """
    import sys
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from engine.models    import TelemetryEvent
    from engine.schema    import parse_chain_yaml
    from engine.state_machine import CorrelationEngine

    # Load chain rules
    chains = []
    for yml in sorted(rules_dir.glob("*.yml")):
        chains.append(parse_chain_yaml(str(yml)))

    engine = CorrelationEngine(chains)

    # Load and replay events
    raw_events = json.loads(fixture_path.read_text(encoding="utf-8-sig"))
    alerts: List[str] = []
    for raw in raw_events:
        if "_comment" in raw:
            raw = {k: v for k, v in raw.items() if k != "_comment"}
        ev = TelemetryEvent.from_dict(raw)
        alerts.extend(engine.ingest(ev))

    return alerts
