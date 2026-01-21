from enum import Enum

class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class PriorityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class IncidentStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    mitigated = "mitigated"
    closed = "closed"

class IndicatorType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    command = "file"