from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Literal

@dataclass
class PortInfo:
    port: int
    proto: Literal["tcp", "udp"]
    banner: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    confidence: int | None = None
    method: str | None = None
    fingerprint: str | None = None
    raw_fingerprint: str | None = None

@dataclass
class HttpInfo:
    url: str
    status: int
    title: str | None
    signatures: list[str]

@dataclass
class ScanReport:
    target: str
    started: datetime
    finished: datetime | None = None
    ports: list[PortInfo] = field(default_factory=list)
    http: list[HttpInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def asdict(self):
        return asdict(self)
