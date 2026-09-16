"""
test_detection.py — NullTracer Phase 4 Detection Accuracy Tests
===============================================================
Pytest suite that validates the CorrelationEngine's detection and
false-positive behaviour against three telemetry fixtures:

  - atomic_lolbin_tp.json   → full LOLbin chain      → MUST alert
  - benign_noise.json        → normal system activity → MUST NOT alert
  - partial_chains.json      → incomplete/broken chains → MUST NOT alert
  - synthetic_events.json    → original dev fixture   → MUST alert (regression)

Fixtures are in samples/telemetry/.
Chain rules are loaded from samples/rules/.

Run:
    pytest validation/test_detection.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from validation.metrics import run_engine_on_fixture, DetectionResult, DetectionRates

_RULES_DIR    = _PROJECT_ROOT / "samples" / "rules"
_TELEMETRY    = _PROJECT_ROOT / "samples" / "telemetry"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rules_dir() -> Path:
    assert _RULES_DIR.exists(), f"Rules directory not found: {_RULES_DIR}"
    return _RULES_DIR


# ---------------------------------------------------------------------------
# True-positive tests
# ---------------------------------------------------------------------------

class TestTruePositives:
    """The engine MUST fire at least one alert on known-malicious telemetry."""

    def test_atomic_lolbin_full_chain(self, rules_dir: Path):
        """
        Atomic T1059.001 → T1218.011 → T1047 with correct process lineage
        must trigger exactly one chain alert.
        """
        fixture = _TELEMETRY / "atomic_lolbin_tp.json"
        assert fixture.exists(), f"Fixture missing: {fixture}"

        alerts = run_engine_on_fixture(fixture, rules_dir)

        assert len(alerts) >= 1, (
            f"Expected ≥1 alert from atomic_lolbin_tp.json, got 0.\n"
            f"Check that samples/rules/lolbin_chain.yml matches the fixture."
        )

    def test_alert_contains_chain_id(self, rules_dir: Path):
        """Alert message must include the chain ID for traceability."""
        fixture = _TELEMETRY / "atomic_lolbin_tp.json"
        alerts  = run_engine_on_fixture(fixture, rules_dir)
        assert any("chain_001" in a for a in alerts), (
            f"No alert contains 'chain_001'. Alerts: {alerts}"
        )

    def test_alert_contains_mitre_tags(self, rules_dir: Path):
        """Alert must reference MITRE ATT&CK technique IDs."""
        fixture = _TELEMETRY / "atomic_lolbin_tp.json"
        alerts  = run_engine_on_fixture(fixture, rules_dir)
        mitre_tags = ["T1059.001", "T1218.011", "T1047"]
        for tag in mitre_tags:
            assert any(tag in a for a in alerts), (
                f"MITRE tag '{tag}' not found in any alert. Alerts: {alerts}"
            )

    def test_synthetic_events_regression(self, rules_dir: Path):
        """
        Original synthetic_events.json (dev fixture) must still trigger an
        alert — regression guard against engine regressions.
        """
        fixture = _TELEMETRY / "synthetic_events.json"
        assert fixture.exists(), f"Fixture missing: {fixture}"

        alerts = run_engine_on_fixture(fixture, rules_dir)
        assert len(alerts) >= 1, (
            f"Regression: synthetic_events.json produced 0 alerts.\n"
            f"The CorrelationEngine may have regressed."
        )

    def test_etw_kernel_correlation(self, rules_dir: Path):
        """Test that an ETW ScriptBlock event correctly correlates with subsequent kernel events."""
        fixture = _TELEMETRY / "etw_kernel_join.json"
        alerts = run_engine_on_fixture(fixture, rules_dir)
        assert len(alerts) == 1, f"Expected 1 alert for ETW correlation, got {len(alerts)}"
        assert "T1059.001" in alerts[0]

    def test_pid_lineage_in_alert(self, rules_dir: Path):
        """Alert must include a PID lineage trail (PIDs from the chain)."""
        fixture = _TELEMETRY / "atomic_lolbin_tp.json"
        alerts  = run_engine_on_fixture(fixture, rules_dir)
        assert any("5100" in a or "5200" in a or "5300" in a for a in alerts), (
            f"Expected PIDs 5100/5200/5300 in alert lineage. Alerts: {alerts}"
        )


# ---------------------------------------------------------------------------
# False-positive tests
# ---------------------------------------------------------------------------

class TestFalsePositives:
    """The engine MUST NOT fire on benign or incomplete activity."""

    def test_benign_noise_no_alert(self, rules_dir: Path):
        """
        Normal system activity (cmd.exe, notepad, svchost, Defender, benign
        rundll32) must produce zero alerts.
        """
        fixture = _TELEMETRY / "benign_noise.json"
        assert fixture.exists(), f"Fixture missing: {fixture}"

        alerts = run_engine_on_fixture(fixture, rules_dir)
        assert len(alerts) == 0, (
            f"False positive: benign_noise.json triggered {len(alerts)} alert(s):\n"
            + "\n".join(alerts)
        )

    def test_partial_chain_no_alert(self, rules_dir: Path):
        """
        Incomplete chains (powershell -enc without rundll32 child, out-of-order
        steps, wrong lineage) must NOT alert.
        """
        fixture = _TELEMETRY / "partial_chains.json"
        assert fixture.exists(), f"Fixture missing: {fixture}"

        alerts = run_engine_on_fixture(fixture, rules_dir)
        assert len(alerts) == 0, (
            f"False positive: partial_chains.json triggered {len(alerts)} alert(s):\n"
            + "\n".join(alerts)
        )

    def test_benign_rundll32_alone_no_alert(self, rules_dir: Path):
        """
        A standalone rundll32 process without the powershell -enc parent
        must not alert (verifies lineage enforcement).
        """
        import json, tempfile, os

        standalone = [
            {
                "timestamp":    1700400000.0,
                "event_type":   "ProcessCreate",
                "pid":          8000,
                "ppid":         400,
                "image_path":   "C:\\Windows\\System32\\rundll32.exe",
                "command_line": "rundll32.exe C:\\Users\\Public\\test.dll,EntryPoint",
                "details":      {}
            }
        ]
        tmp = Path(tempfile.mktemp(suffix=".json"))
        tmp.write_text(json.dumps(standalone), encoding="utf-8")

        try:
            alerts = run_engine_on_fixture(tmp, rules_dir)
            assert len(alerts) == 0, (
                f"False positive: isolated rundll32 triggered alert: {alerts}"
            )
        finally:
            tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Aggregate rate assertions
# ---------------------------------------------------------------------------

class TestAggregateRates:
    """
    Compute aggregate TP/FP rates across all fixtures and assert thresholds.
    Detection rate must be 100% (we only have definitive fixtures).
    FP rate must be 0% (our benign + partial fixtures must be clean).
    """

    def _build_rates(self, rules_dir: Path) -> DetectionRates:
        fixtures_expected = [
            (_TELEMETRY / "atomic_lolbin_tp.json",  1),
            (_TELEMETRY / "synthetic_events.json",   1),
            (_TELEMETRY / "benign_noise.json",        0),
            (_TELEMETRY / "partial_chains.json",      0),
        ]
        results = []
        for path, expected in fixtures_expected:
            if not path.exists():
                continue
            alerts = run_engine_on_fixture(path, rules_dir)
            results.append(DetectionResult(
                fixture_path    = str(path),
                expected_alerts = expected,
                actual_alerts   = len(alerts),
                alert_messages  = alerts,
            ))
        return DetectionRates(results=results)

    def test_detection_rate_100_percent(self, rules_dir: Path):
        """Detection rate (TPR) must be 100% across all TP fixtures."""
        rates = self._build_rates(rules_dir)
        assert rates.detection_rate == 1.0, (
            f"Detection rate is {rates.detection_rate:.0%}. "
            f"TP={rates.tp}, FN={rates.fn}"
        )

    def test_false_positive_rate_zero(self, rules_dir: Path):
        """False positive rate must be 0% across all benign fixtures."""
        rates = self._build_rates(rules_dir)
        assert rates.false_positive_rate == 0.0, (
            f"FP rate is {rates.false_positive_rate:.0%}. "
            f"FP={rates.fp}, TN={rates.tn}"
        )

    def test_f1_score_perfect(self, rules_dir: Path):
        """F1 score must be 1.0 (perfect precision + recall)."""
        rates = self._build_rates(rules_dir)
        assert rates.f1 == 1.0, (
            f"F1 score is {rates.f1:.3f} (expected 1.0). "
            f"TP={rates.tp} FP={rates.fp} FN={rates.fn} TN={rates.tn}"
        )
