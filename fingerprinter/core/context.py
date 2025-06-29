from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, AddressValueError
from typing import Union, Optional
from pathlib import Path
import re

@dataclass(frozen=True, slots=True)
class ScanTarget:
    """Represents a scan target with automatic type detection."""
    value: str
    target_type: Optional[str] = None

    def __post_init__(self):
        if self.target_type is None:
            # Auto-detect target type
            detected_type = self._detect_type()
            object.__setattr__(self, 'target_type', detected_type)

    def _detect_type(self) -> str:
        """Automatically detect the target type based on the value."""
        # Try IP address
        try:
            ip_address(self.value)
            return 'ip'
        except (AddressValueError, ValueError):
            pass

        # Check for hostname/domain (must contain at least one dot)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
        if re.match(hostname_pattern, self.value) and '.' in self.value:
            return 'hostname'

        # Check for URL
        if self.value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Check for MAC address
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        if re.match(mac_pattern, self.value):
            return 'mac'

        # Check for Bluetooth address
        if re.match(mac_pattern, self.value):
            return 'bluetooth'

        # Check for geographic coordinates
        coord_pattern = r'^-?\d+\.?\d*,-?\d+\.?\d*$'
        if re.match(coord_pattern, self.value):
            return 'coordinates'

        # Check for file path
        if Path(self.value).exists() or '/' in self.value or '\\' in self.value:
            return 'file'

        # Default to generic identifier
        return 'identifier'

    @property
    def is_ip(self) -> bool:
        """Check if target is an IP address."""
        return self.target_type == 'ip'

    @property
    def is_network_target(self) -> bool:
        """Check if target is network-addressable."""
        return self.target_type in ['ip', 'hostname', 'url']

    @property
    def ip(self):
        """Get IP address object if target is an IP, otherwise None."""
        if self.is_ip:
            return ip_address(self.value)
        return None

    def safe_filename(self) -> str:
        """Generate a safe filename from the target value."""
        # Replace problematic characters
        safe = re.sub(r'[^\w\-_.]', '_', self.value)
        # Remove multiple underscores
        safe = re.sub(r'_+', '_', safe)
        # Limit length
        if len(safe) > 50:
            safe = safe[:50]
        return safe

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Configuration and context for a scan operation."""
    target: Union[str, ScanTarget]
    scan_id: Optional[str] = None
    start: datetime = field(default_factory=datetime.utcnow)
    timeout: float = 3.0
    interactive: bool = False
    legal_ok: bool = False
    location: Optional[str] = None  # Physical location context
    notes: list[str] = field(default_factory=list)  # User-provided context notes

    def __post_init__(self):
        # Ensure target is a ScanTarget object
        if isinstance(self.target, str):
            object.__setattr__(self, 'target', ScanTarget(self.target))

        # Generate scan_id if not provided
        if self.scan_id is None:
            timestamp = self.start.strftime("%Y%m%d_%H%M%S")
            object.__setattr__(self, 'scan_id', f"{self.target.safe_filename()}_{timestamp}")

    @property
    def ip(self):
        """Legacy property for backward compatibility."""
        if self.target.is_ip:
            return self.target.ip
        raise ValueError(f"Target '{self.target}' is not an IP address (type: {self.target.target_type})")

    @property
    def target_value(self) -> str:
        """Get the raw target value."""
        return self.target.value

    @property
    def target_type(self) -> str:
        """Get the detected target type."""
        return self.target.target_type

    @property
    def is_network_scan(self) -> bool:
        """Check if this is a network-based scan."""
        return self.target.is_network_target

    @property
    def display_name(self) -> str:
        """Get a human-readable display name for the target."""
        if self.target_type == 'ip':
            return f"IP {self.target_value}"
        elif self.target_type == 'hostname':
            return f"Host {self.target_value}"
        elif self.target_type == 'coordinates':
            return f"Location {self.target_value}"
        elif self.target_type == 'identifier':
            return f"Target {self.target_value}"
        else:
            return f"{self.target_type.title()} {self.target_value}"

    def json_out(self) -> str:
        """Generate output filename for JSON results."""
        return f"scan_{self.scan_id}.json"

    def supports_scanner(self, scanner_name: str) -> bool:
        """Check if a scanner is compatible with this target type."""
        scanner_compatibility = {
            'nmap': ['ip', 'hostname'],
            'http': ['ip', 'hostname', 'url'],
            'port': ['ip', 'hostname'],
            'arp': ['ip'],
            'hackrf': ['*'],  # RF scanning works with any target (used for context/location)
            'bluetooth': ['bluetooth', 'mac', '*'],
            'wifi': ['*'],  # WiFi scanning works with any target
            'gps': ['coordinates', '*'],
            'file': ['file'],
        }

        if scanner_name not in scanner_compatibility:
            return True  # Unknown scanners are assumed compatible

        compatible_types = scanner_compatibility[scanner_name]

        # '*' means compatible with any target type
        if '*' in compatible_types:
            return True

        return self.target_type in compatible_types

    def get_context_description(self) -> str:
        """Generate a description of the scan context."""
        parts = [f"Target: {self.display_name}"]

        if self.location:
            parts.append(f"Location: {self.location}")

        if self.notes:
            parts.append(f"Notes: {'; '.join(self.notes)}")

        return " | ".join(parts)


def create_scan_context(target: str, **kwargs) -> ScanContext:
    """Factory function to create a ScanContext with proper target detection."""
    return ScanContext(target=target, **kwargs)


# Convenience functions for specific target types
def ip_scan_context(ip_address: str, **kwargs) -> ScanContext:
    """Create a scan context specifically for IP address scanning."""
    target = ScanTarget(ip_address, target_type='ip')
    return ScanContext(target=target, **kwargs)


def location_scan_context(coordinates: str, location_name: str = None, **kwargs) -> ScanContext:
    """Create a scan context for location-based scanning (e.g., RF surveys)."""
    target = ScanTarget(coordinates, target_type='coordinates')
    if location_name:
        kwargs['location'] = location_name
    return ScanContext(target=target, **kwargs)


def rf_scan_context(identifier: str, location: str = None, **kwargs) -> ScanContext:
    """Create a scan context for RF spectrum scanning."""
    target = ScanTarget(identifier, target_type='identifier')
    if location:
        kwargs['location'] = location
    return ScanContext(target=target, **kwargs)
