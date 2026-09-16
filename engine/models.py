from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum

class EventType(Enum):
    PROCESS_CREATE = "ProcessCreate"
    IMAGE_LOAD = "ImageLoad"
    REGISTRY_SET = "RegistrySet"

@dataclass
class TelemetryEvent:
    timestamp: float
    event_type: EventType
    pid: int
    ppid: Optional[int]
    image_path: str
    command_line: Optional[str]
    details: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TelemetryEvent':
        return cls(
            timestamp=data['timestamp'],
            event_type=EventType(data['event_type']),
            pid=data['pid'],
            ppid=data.get('ppid'),
            image_path=data['image_path'],
            command_line=data.get('command_line'),
            details=data.get('details', {})
        )
