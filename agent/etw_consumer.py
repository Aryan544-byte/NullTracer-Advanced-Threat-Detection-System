"""
etw_consumer.py — Phase 4 ETW Consumer
=======================================
Consumes ETW events from the Microsoft-Windows-PowerShell provider using
pywintrace. Extracts Event ID 4104 (ScriptBlock) to uncover obfuscated
command executions.
"""

import threading
import logging
from typing import Iterator, Optional
import etw
from etw.etw import ProviderInfo
from etw.GUID import GUID

from engine.models import TelemetryEvent, EventType

log = logging.getLogger("nulltracer.etw")

class EtwConsumer:
    """
    Subscribes to Microsoft-Windows-PowerShell ETW provider.
    Runs on a background thread and queues parsed TelemetryEvents.
    """
    PROVIDER_NAME = "Microsoft-Windows-PowerShell"
    PROVIDER_GUID = "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"

    def __init__(self):
        self._events = []
        self._lock = threading.Lock()
        self._job = None
        self._thread = None
        self._stop_event = threading.Event()

    def _on_event(self, raw_event):
        """Callback from pywintrace for each event."""
        event_id = raw_event[0]
        payload = raw_event[1]
        
        # We only care about ScriptBlock execution (4104)
        if event_id != 4104:
            return
            
        try:
            header = payload.get("EventHeader", {})
            pid = header.get("ProcessId")
            
            # Timestamp is in Windows FILETIME format (100ns intervals since 1601)
            # etw library returns it in the header.
            # However, for simplicity, we can just use current time if it's live, 
            # or convert it properly if needed. etw gives a raw integer.
            timestamp_ft = header.get("TimeStamp", 0)
            timestamp_unix = (timestamp_ft - 116444736000000000) / 1e7 if timestamp_ft else 0.0
            
            # The payload contains ScriptBlockText
            script_block = payload.get("ScriptBlockText", "")
            if not script_block:
                return

            event = TelemetryEvent(
                timestamp=timestamp_unix,
                event_type=EventType.PROCESS_CREATE, # Map to ProcessCreate for engine matching
                pid=pid,
                ppid=None, # ETW doesn't provide PPID directly here
                image_path="powershell.exe", # Virtualize image path
                command_line=script_block, # Use script block as command line
                details={"source": "etw_4104"}
            )
            
            with self._lock:
                self._events.append(event)
                
        except Exception as e:
            log.debug("Failed to parse ETW event: %s", e)

    def start(self):
        """Start the ETW capture in a background thread."""
        log.info("Starting ETW consumer for %s", self.PROVIDER_NAME)
        providers = [ProviderInfo(self.PROVIDER_NAME, GUID(self.PROVIDER_GUID))]
        
        # Start ETW session
        self._job = etw.ETW(providers=providers, event_callback=self._on_event)
        
        def run_job():
            try:
                self._job.start()
            except Exception as e:
                log.error("ETW capture failed: %s", e)
                
        self._thread = threading.Thread(target=run_job, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the ETW capture."""
        if self._job:
            self._job.stop()
            self._thread.join(timeout=2)
            log.info("ETW consumer stopped.")

    def poll_events(self) -> list[TelemetryEvent]:
        """Return all events captured since the last poll."""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events
