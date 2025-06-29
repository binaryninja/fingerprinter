from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address

@dataclass(frozen=True, slots=True)
class ScanContext:
    target: str
    start: datetime = field(default_factory=datetime.utcnow)
    timeout: float = 3.0
    interactive: bool = False
    legal_ok: bool = False

    @property
    def ip(self):
        return ip_address(self.target)

    def json_out(self):
        safe = str(self.ip).replace(":", "_").replace(".", "_")
        return f"scan_{safe}.json"
