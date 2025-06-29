from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Literal, Optional

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
class FrequencyBin:
    frequency_hz: float
    power_db: float
    bandwidth_hz: float
    detection_method: str
    timestamp: datetime

@dataclass
class RfScanInfo:
    center_freq_hz: float
    sample_rate_hz: float
    bandwidth_hz: float
    gain_db: int
    hot_bins: list[FrequencyBin]
    scan_duration_sec: float
    total_samples: int
    noise_floor_db: float
    detection_threshold_db: float

@dataclass
class HttpInfo:
    url: str
    status: int
    title: str | None
    signatures: list[str]

@dataclass
class ScanReport:
    target: str
    target_type: str
    scan_id: str
    started: datetime
    finished: datetime | None = None
    location: str | None = None
    context_notes: list[str] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    http: list[HttpInfo] = field(default_factory=list)
    rf_scans: list[RfScanInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # Scanner-generated notes
    scanner_results: dict = field(default_factory=dict)  # Future extensibility

    @property
    def display_target(self) -> str:
        """Get a human-readable target description."""
        if self.target_type == 'ip':
            return f"IP {self.target}"
        elif self.target_type == 'hostname':
            return f"Host {self.target}"
        elif self.target_type == 'coordinates':
            return f"Location {self.target}"
        elif self.target_type == 'identifier':
            return f"Target {self.target}"
        else:
            return f"{self.target_type.title()} {self.target}"

    @property
    def is_network_scan(self) -> bool:
        """Check if this report contains network scan results."""
        return self.target_type in ['ip', 'hostname', 'url'] or bool(self.ports or self.http)

    @property
    def has_rf_data(self) -> bool:
        """Check if this report contains RF scan results."""
        return bool(self.rf_scans)

    @property
    def total_open_ports(self) -> int:
        """Get total number of open ports discovered."""
        return len(self.ports)

    def get_context_summary(self) -> str:
        """Generate a summary of the scan context."""
        parts = [f"Target: {self.display_target}"]

        if self.location:
            parts.append(f"Location: {self.location}")

        if self.context_notes:
            parts.append(f"Context: {'; '.join(self.context_notes)}")

        return " | ".join(parts)

    def asdict(self):
        return asdict(self)
