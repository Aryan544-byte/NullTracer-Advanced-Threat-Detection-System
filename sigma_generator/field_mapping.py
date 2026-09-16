"""
field_mapping.py — NullTracer Sigma Auto-Generator
===================================================
Defines the mapping from NullTracer's internal kernel/ETW field names to
the Sigma common schema field names.

WHY: Sigma rules use a standardized field vocabulary (e.g., `Image` instead
of `image_path`). Rather than hardcoding translations inside the rule-builder,
we centralize them here so adding a new telemetry source only requires
updating this table, not touching rule logic.

Source schema reference:
  Sigma field taxonomy: https://github.com/SigmaHQ/sigma-specification
  NullTracer fields: defined in engine/models.py
"""

from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Core field map: NullTracer internal field -> Sigma common schema field
# ---------------------------------------------------------------------------
# The key is the field name as it appears in our TelemetryEvent / ETW record.
# The value is the canonical Sigma field name used in detection blocks.

PROCESS_FIELD_MAP: Dict[str, str] = {
    # Process identity
    "image_path":         "Image",
    "pid":                "ProcessId",
    "ppid":               "ParentProcessId",
    "parent_image":       "ParentImage",
    "command_line":       "CommandLine",
    "user":               "User",
    "logon_guid":         "LogonGuid",
    "logon_id":           "LogonId",
    "terminal_session_id":"TerminalSessionId",
    "integrity_level":    "IntegrityLevel",
    "hashes":             "Hashes",
    "current_directory":  "CurrentDirectory",
    "imphash":            "Imphash",
    "company":            "Company",
    "description":        "Description",
    "product":            "Product",
    "file_version":       "FileVersion",
    # Parent process
    "parent_command_line":"ParentCommandLine",
    "parent_user":        "ParentUser",
}

IMAGE_LOAD_FIELD_MAP: Dict[str, str] = {
    "image_path":         "Image",
    "pid":                "ProcessId",
    "image_loaded":       "ImageLoaded",
    "hashes":             "Hashes",
    "signed":             "Signed",
    "signature":          "Signature",
    "signature_status":   "SignatureStatus",
}

REGISTRY_FIELD_MAP: Dict[str, str] = {
    "image_path":         "Image",
    "pid":                "ProcessId",
    "registry_key":       "TargetObject",
    "registry_value":     "Details",
    "registry_op":        "EventType",
}

# ---------------------------------------------------------------------------
# Sigma log-source category mapping per NullTracer event type
# ---------------------------------------------------------------------------
# Maps NullTracer EventType enum values to the Sigma logsource category string.
# "process_creation" is the broadest and most backend-compatible category.

LOGSOURCE_MAP: Dict[str, Dict[str, str]] = {
    "ProcessCreate": {
        "category": "process_creation",
        "product":  "windows",
    },
    "ImageLoad": {
        "category": "image_load",
        "product":  "windows",
    },
    "RegistrySet": {
        "category": "registry_set",
        "product":  "windows",
    },
}

# ---------------------------------------------------------------------------
# Translate a single field from NullTracer space into Sigma space.
# Returns None if no mapping is found (caller should skip or log the field).
# ---------------------------------------------------------------------------

def translate_field(event_type: str, internal_field: str) -> Optional[str]:
    """
    Look up the Sigma-canonical field name for a given NullTracer field.

    Args:
        event_type:     One of "ProcessCreate", "ImageLoad", "RegistrySet".
        internal_field: The NullTracer-internal field name (snake_case).

    Returns:
        Sigma field name string, or None if the field has no mapping.
    """
    if event_type == "ProcessCreate":
        return PROCESS_FIELD_MAP.get(internal_field)
    elif event_type == "ImageLoad":
        return IMAGE_LOAD_FIELD_MAP.get(internal_field)
    elif event_type == "RegistrySet":
        return REGISTRY_FIELD_MAP.get(internal_field)
    return None
