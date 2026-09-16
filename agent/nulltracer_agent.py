"""
nulltracer_agent.py — NullTracer User-Mode Relay Agent
=======================================================
Bridges the kernel driver (NullTracerDrv.sys) to the Phase 1
CorrelationEngine and Phase 2 Sigma auto-generator.

Architecture:
  ┌─────────────────────────────────────────────┐
  │  NullTracerDrv.sys  (kernel, Ring 0)         │
  │  Ring buffer with NT_EVENT_RECORD structs    │
  └──────────────┬──────────────────────────────┘
                 │  IOCTL_NULLTRACER_READ_EVENTS
                 │  DeviceIoControl via ctypes
  ┌──────────────▼──────────────────────────────┐
  │  EventDeserializer                           │
  │  NT_EVENT_RECORD → TelemetryEvent            │
  └──────────────┬──────────────────────────────┘
                 │
  ┌──────────────▼──────────────────────────────┐
  │  CorrelationEngine  (Phase 1)                │
  │  Sliding-window attack-chain detection       │
  └──────────────┬──────────────────────────────┘
                 │  alert fired
  ┌──────────────▼──────────────────────────────┐
  │  SigmaAutoGenerator  (Phase 2)               │
  │  Invokes sigma_generator.cli                 │
  │  Writes Sigma YAML + SPL/KQL/Lucene         │
  └──────────────┬──────────────────────────────┘
                 │
  ┌──────────────▼──────────────────────────────┐
  │  AlertLogger                                 │
  │  Appends to agent/alerts.jsonl               │
  └─────────────────────────────────────────────┘

Usage:
    # Run as Administrator (requires the driver to be loaded):
    python -m agent.nulltracer_agent

    # Replay a saved event file instead of reading the live driver:
    python -m agent.nulltracer_agent --replay samples/telemetry/synthetic_events.json

    # Specify a rule directory:
    python -m agent.nulltracer_agent --rules samples/rules/ --output samples/sigma_output/

    # Show ring-buffer statistics and exit:
    python -m agent.nulltracer_agent --stats
"""

import argparse
import ctypes
import ctypes.wintypes
import json
import logging
import os
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

# ---------------------------------------------------------------------------
# Add project root to sys.path so we can import engine and sigma_generator
# ---------------------------------------------------------------------------
_AGENT_DIR   = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from agent.etw_consumer import EtwConsumer
except ImportError:
    EtwConsumer = None

from engine.models import TelemetryEvent, EventType
from engine.schema import parse_chain_yaml, AttackChain
from engine.state_machine import CorrelationEngine
from sigma_generator.rule_builder import build_sigma_rule
from sigma_generator.compiler import rule_dict_to_sigma_yaml, compile_rule

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("nulltracer.agent")

# ---------------------------------------------------------------------------
# IOCTL constants — must match driver/NullTracerDrv/ioctl.h
# ---------------------------------------------------------------------------
NULLTRACER_WIN32_NAME       = r"\\.\NullTracer"

FILE_DEVICE_UNKNOWN         = 0x00000022
METHOD_BUFFERED             = 0
FILE_READ_DATA              = 0x0001

def _CTL_CODE(device_type: int, func: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (func << 2) | method

IOCTL_NULLTRACER_READ_EVENTS = _CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
IOCTL_NULLTRACER_GET_STATS   = _CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

# ---------------------------------------------------------------------------
# NT_EVENT_RECORD layout — must match driver/NullTracerDrv/ioctl.h (packed)
#
#   ULONG64   Timestamp           8 bytes
#   ULONG     EventType           4 bytes
#   ULONG     ProcessId           4 bytes
#   ULONG     ParentProcessId     4 bytes
#   ULONG     ThreadId            4 bytes
#   WCHAR[260] ImagePath         520 bytes
#   WCHAR[512] CommandLine      1024 bytes
#   WCHAR[256] RegistryKey       512 bytes
#   WCHAR[260] RegistryValue     520 bytes
#   ULONG     Reserved            4 bytes
#   Total:                      2604 bytes
# ---------------------------------------------------------------------------
NT_MAX_PATH_CCH    = 260
NT_MAX_CMDLINE_CCH = 512
NT_MAX_REGKEY_CCH  = 256

_RECORD_FMT = (
    "Q"          # Timestamp  (ULONG64)
    "I"          # EventType  (ULONG)
    "I"          # ProcessId  (ULONG)
    "I"          # ParentProcessId (ULONG)
    "I"          # ThreadId   (ULONG)
    f"{NT_MAX_PATH_CCH * 2}s"    # ImagePath   (WCHAR array → bytes)
    f"{NT_MAX_CMDLINE_CCH * 2}s" # CommandLine (WCHAR array → bytes)
    f"{NT_MAX_REGKEY_CCH * 2}s"  # RegistryKey (WCHAR array → bytes)
    f"{NT_MAX_PATH_CCH * 2}s"    # RegistryValue (WCHAR array → bytes)
    "I"          # Reserved   (ULONG)
)
_RECORD_SIZE = struct.calcsize(_RECORD_FMT)

# NT_STATS layout
_STATS_FMT  = "QQQII"
_STATS_SIZE = struct.calcsize(_STATS_FMT)

# NT_EVENT_TYPE codes
_NT_EVENT_PROCESS_CREATE = 0x01
_NT_EVENT_IMAGE_LOAD     = 0x02
_NT_EVENT_REGISTRY_SET   = 0x03

_EVENT_TYPE_MAP = {
    _NT_EVENT_PROCESS_CREATE: EventType.PROCESS_CREATE,
    _NT_EVENT_IMAGE_LOAD:     EventType.IMAGE_LOAD,
    _NT_EVENT_REGISTRY_SET:   EventType.REGISTRY_SET,
}

# Windows FILETIME epoch offset (100-ns ticks between 1601-01-01 and 1970-01-01)
_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000

# ---------------------------------------------------------------------------
# Windows API via ctypes
# ---------------------------------------------------------------------------
_kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None

GENERIC_READ         = 0x80000000
OPEN_EXISTING        = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value


def _open_device(path: str):
    """Open the NullTracer device and return a handle (raises OSError on failure)."""
    if _kernel32 is None:
        raise RuntimeError("This agent requires Windows (win32).")

    handle = _kernel32.CreateFileW(
        path,
        GENERIC_READ,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(
            f"CreateFile({path!r}) failed with error {err}. "
            "Is the driver loaded? (Run setup_testsign.ps1 first.)"
        )
    return handle


def _close_device(handle) -> None:
    if _kernel32 and handle != INVALID_HANDLE_VALUE:
        _kernel32.CloseHandle(handle)


def _device_ioctl(handle, ioctl_code: int, in_buf: bytes, out_size: int) -> bytes:
    """Issue a DeviceIoControl call and return the output bytes."""
    out_buf  = ctypes.create_string_buffer(out_size)
    returned = ctypes.wintypes.DWORD(0)

    ok = _kernel32.DeviceIoControl(
        handle,
        ioctl_code,
        in_buf if in_buf else None,
        len(in_buf) if in_buf else 0,
        out_buf,
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        err = ctypes.get_last_error()
        raise OSError(f"DeviceIoControl failed with error {err}")

    return bytes(out_buf.raw[: returned.value])


# ---------------------------------------------------------------------------
# EventDeserializer — unpack raw bytes → TelemetryEvent
# ---------------------------------------------------------------------------

class EventDeserializer:
    """
    Converts raw NT_EVENT_RECORD bytes from the driver into TelemetryEvent
    objects understood by the Phase 1 CorrelationEngine.
    """

    @staticmethod
    def _decode_wstr(raw: bytes) -> str:
        """Decode a null-terminated UTF-16LE byte blob."""
        text = raw.decode("utf-16-le", errors="replace")
        nul  = text.find("\x00")
        return text[:nul] if nul != -1 else text

    @staticmethod
    def _filetime_to_unix(ft: int) -> float:
        """Convert a Windows FILETIME (100-ns ticks since 1601) to Unix timestamp."""
        return (ft - _FILETIME_EPOCH_OFFSET) / 1e7

    @classmethod
    def unpack_batch(cls, data: bytes) -> List[TelemetryEvent]:
        """Unpack a raw byte buffer containing N NT_EVENT_RECORD structs."""
        events: List[TelemetryEvent] = []
        offset = 0
        while offset + _RECORD_SIZE <= len(data):
            fields = struct.unpack_from(_RECORD_FMT, data, offset)
            offset += _RECORD_SIZE

            (timestamp, event_type_code, pid, ppid, tid,
             raw_image, raw_cmdline, raw_regkey, raw_regval, _reserved) = fields

            et = _EVENT_TYPE_MAP.get(event_type_code)
            if et is None:
                continue  # unknown event type — skip

            image_path   = cls._decode_wstr(raw_image)
            command_line = cls._decode_wstr(raw_cmdline) or None
            reg_key      = cls._decode_wstr(raw_regkey)
            reg_val      = cls._decode_wstr(raw_regval)

            details = {}
            if et == EventType.REGISTRY_SET:
                if reg_key:
                    details["registry_key"]   = reg_key
                if reg_val:
                    details["registry_value"] = reg_val

            events.append(TelemetryEvent(
                timestamp    = cls._filetime_to_unix(timestamp),
                event_type   = et,
                pid          = pid,
                ppid         = ppid if ppid else None,
                image_path   = image_path,
                command_line = command_line,
                details      = details,
            ))
        return events


# ---------------------------------------------------------------------------
# AlertLogger
# ---------------------------------------------------------------------------

class AlertLogger:
    """Appends alert records to a JSONL file for persistence."""

    def __init__(self, log_path: Path):
        self._path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert_text: str, events: Optional[List[TelemetryEvent]] = None) -> None:
        record = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "alert":     alert_text,
        }
        if events:
            record["pids"] = [e.pid for e in events]
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# SigmaAutoGenerator — wraps Phase 2 on alert
# ---------------------------------------------------------------------------

class SigmaAutoGenerator:
    """
    Invoked when the CorrelationEngine fires an alert.
    Generates Sigma YAML + SPL/KQL/Lucene and writes them to output_dir.
    """

    def __init__(self, output_dir: Path):
        self._out = output_dir
        self._out.mkdir(parents=True, exist_ok=True)

    def generate(self, chain: AttackChain, alert_text: str) -> None:
        log.info("Generating Sigma rule for chain '%s'...", chain.id)
        rule_dict = build_sigma_rule(chain)
        sigma_yaml = rule_dict_to_sigma_yaml(rule_dict)

        yaml_path = self._out / f"{chain.id}_auto.yml"
        yaml_path.write_text(sigma_yaml, encoding="utf-8")
        log.info("  → Sigma YAML: %s", yaml_path)

        try:
            compiled = compile_rule(rule_dict)
            for backend, query in compiled.items():
                if query and not query.startswith("#"):
                    out_file = self._out / f"{chain.id}_auto_{backend}.txt"
                    out_file.write_text(query, encoding="utf-8")
                    log.info("  → %s query: %s", backend.upper(), out_file)
                else:
                    log.warning("  ! %s backend: %s", backend, query)
        except Exception as exc:
            log.warning("  ! Sigma compilation error: %s", exc)


# ---------------------------------------------------------------------------
# Live driver reader
# ---------------------------------------------------------------------------

class DriverEventReader:
    r"""
    Continuously reads NT_EVENT_RECORD batches from \\.\NullTracer via IOCTL.
    Yields TelemetryEvent objects.
    """
    BATCH_SIZE    = 256      # events per IOCTL call
    POLL_INTERVAL = 0.1      # seconds between polls when ring is empty

    def __init__(self, device_path: str = NULLTRACER_WIN32_NAME):
        self._device_path = device_path
        self._handle      = None

    def __enter__(self):
        log.info("Opening NullTracer device: %s", self._device_path)
        self._handle = _open_device(self._device_path)
        log.info("Device opened successfully.")
        return self

    def __exit__(self, *args):
        if self._handle:
            _close_device(self._handle)
            self._handle = None

    def read_events(self) -> Iterator[TelemetryEvent]:
        """Continuously yield TelemetryEvents from the kernel ring buffer."""
        in_buf  = struct.pack("I", self.BATCH_SIZE)
        out_size = self.BATCH_SIZE * _RECORD_SIZE

        while True:
            raw = _device_ioctl(
                self._handle,
                IOCTL_NULLTRACER_READ_EVENTS,
                in_buf,
                out_size,
            )
            events = EventDeserializer.unpack_batch(raw)
            if events:
                for ev in events:
                    yield ev
            else:
                time.sleep(self.POLL_INTERVAL)

    def get_stats(self) -> dict:
        """Return ring buffer statistics as a dict."""
        raw = _device_ioctl(
            self._handle,
            IOCTL_NULLTRACER_GET_STATS,
            b"",
            _STATS_SIZE,
        )
        (produced, consumed, dropped, capacity, occupancy) = struct.unpack(_STATS_FMT, raw)
        return {
            "total_produced": produced,
            "total_consumed": consumed,
            "total_dropped":  dropped,
            "ring_capacity":  capacity,
            "ring_occupancy": occupancy,
        }


# ---------------------------------------------------------------------------
# Replay reader (for --replay flag, no driver needed)
# ---------------------------------------------------------------------------

class ReplayEventReader:
    """
    Reads events from a synthetic_events.json file for testing without
    the kernel driver installed.
    """

    def __init__(self, json_path: Path):
        self._path = json_path

    def read_events(self) -> Iterator[TelemetryEvent]:
        with self._path.open(encoding="utf-8-sig") as f:
            raw_events = json.load(f)

        log.info("Replaying %d events from %s", len(raw_events), self._path)
        for raw in raw_events:
            yield TelemetryEvent.from_dict(raw)
            time.sleep(0.05)   # small delay to simulate real-time stream

    def get_stats(self) -> dict:
        return {"mode": "replay"}


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------

def _load_chains(rules_dir: Path) -> List[AttackChain]:
    chains = []
    for yml in rules_dir.glob("*.yml"):
        try:
            chain = parse_chain_yaml(str(yml))
            chains.append(chain)
            log.info("Loaded chain rule: %s (%s steps)", chain.id, len(chain.steps))
        except Exception as exc:
            log.warning("Failed to parse %s: %s", yml, exc)
    if not chains:
        log.warning("No chain rules found in %s", rules_dir)
    return chains


def run_agent(
    rules_dir:   Path,
    output_dir:  Path,
    alert_log:   Path,
    replay_path: Optional[Path] = None,
    stats_only:  bool           = False,
) -> None:
    """
    Main agent entry point.

    Args:
        rules_dir:   Directory containing NullTracer chain YAML rules.
        output_dir:  Directory where Sigma output files are written.
        alert_log:   Path to the JSONL alert log file.
        replay_path: If set, replay events from this JSON file (no driver needed).
        stats_only:  If True, print ring buffer stats and exit.
    """
    # --- Load chain rules ---
    chains = _load_chains(rules_dir)
    if not chains:
        log.error("Cannot start: no chain rules loaded. Exiting.")
        sys.exit(1)

    engine   = CorrelationEngine(chains)
    # Build a chain lookup by id for Sigma generation
    chain_by_id = {c.id: c for c in chains}

    alert_logger = AlertLogger(alert_log)
    sigma_gen    = SigmaAutoGenerator(output_dir)

    def _process_event(event: TelemetryEvent) -> None:
        log.debug("Event: type=%s pid=%d image=%s",
                  event.event_type.value, event.pid,
                  os.path.basename(event.image_path))
        alerts = engine.ingest(event)
        for alert in alerts:
            log.warning("🚨 %s", alert)
            alert_logger.write(alert)

            # Extract chain ID from the alert string and generate Sigma
            for chain_id, chain in chain_by_id.items():
                if chain_id in alert:
                    sigma_gen.generate(chain, alert)
                    break

    # --- Stats-only mode ---
    if stats_only:
        if replay_path:
            print(json.dumps({"mode": "replay", "path": str(replay_path)}, indent=2))
            return
        try:
            with DriverEventReader() as reader:
                stats = reader.get_stats()
            print(json.dumps(stats, indent=2))
        except OSError as e:
            log.error("Cannot open device: %s", e)
            sys.exit(1)
        return

    # --- Replay mode ---
    if replay_path:
        log.info("=== REPLAY MODE === (no driver required)")
        reader = ReplayEventReader(replay_path)
        for event in reader.read_events():
            _process_event(event)
        log.info("Replay complete. Processed all events.")
        return

    # --- Live mode ---
    log.info("=== LIVE MODE === (reading from kernel driver + ETW)")
    log.info("Press Ctrl+C to stop.")
    
    etw_consumer = EtwConsumer() if EtwConsumer else None
    if etw_consumer:
        etw_consumer.start()
        
    try:
        with DriverEventReader() as reader:
            for event in reader.read_events():
                _process_event(event)
                
                # Interleave ETW events
                if etw_consumer:
                    for etw_event in etw_consumer.poll_events():
                        _process_event(etw_event)
                        
    except KeyboardInterrupt:
        log.info("Agent stopped by user.")
    except OSError as e:
        log.error("Device error: %s", e)
        log.error("Make sure NullTracerDrv.sys is loaded. Run: .\\driver\\setup_testsign.ps1")
        sys.exit(1)
    finally:
        if etw_consumer:
            etw_consumer.stop()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NullTracer User-Mode Relay Agent — Phase 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=_PROJECT_ROOT / "samples" / "rules",
        help="Directory containing NullTracer chain YAML rule files (default: samples/rules/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_PROJECT_ROOT / "samples" / "sigma_output",
        help="Directory for Sigma YAML / SPL / KQL output (default: samples/sigma_output/)",
    )
    parser.add_argument(
        "--alerts",
        type=Path,
        default=_AGENT_DIR / "alerts.jsonl",
        help="JSONL file for persisted alert log (default: agent/alerts.jsonl)",
    )
    parser.add_argument(
        "--replay",
        type=Path,
        default=None,
        metavar="JSON_FILE",
        help="Replay events from a synthetic JSON file instead of reading the driver",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print ring buffer statistics and exit (driver must be loaded)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("NullTracer Agent starting")
    log.info("  Rules dir : %s", args.rules)
    log.info("  Output dir: %s", args.output)
    log.info("  Alert log : %s", args.alerts)

    run_agent(
        rules_dir   = args.rules,
        output_dir  = args.output,
        alert_log   = args.alerts,
        replay_path = args.replay,
        stats_only  = args.stats,
    )


if __name__ == "__main__":
    main()
