from dataclasses import dataclass
from typing import Optional


@dataclass
class Event:
    timestamp: str
    source_ip: str
    service: str
    event_type: str
    details: Optional[str] = None


@dataclass
class Incident:
    start_time: str
    source_ip: str
    attack_type: str
    severity: str
    threat_score: int
    status: str = "OPEN"
    end_time: Optional[str] = None


@dataclass
class Service:
    service_name: str
    port: int
    status: str = "ACTIVE"


@dataclass
class DetectionRule:
    rule_name: str
    attack_type: str
    threshold: int