import importlib
import pkgutil
import asyncio
from datetime import datetime
from typing import Iterable
from fingerprinter.core.result import ScanReport
from fingerprinter.core.context import ScanContext

mods = [m.name for m in pkgutil.iter_modules(__path__) if m.name != "__init__"]

def available() -> list[str]:
    return mods

async def run_scanners(ctx: ScanContext,
                       only: Iterable[str] | None,
                       log) -> ScanReport:
    report = ScanReport(target=str(ctx.ip), started=ctx.start)

    async def _run(name: str):
        if only and name not in only:
            return
        try:
            mod = importlib.import_module(f".{name}", package=__package__)
            if not hasattr(mod, "scan"):
                log.warning(f"Scanner {name} has no .scan() function.")
                return
            await mod.scan(ctx, report, log)
        except Exception as exc:
            log.exception(f"Scanner '{name}' failed: {exc}")

    await asyncio.gather(*[_run(m) for m in mods])
    report.finished = datetime.utcnow()

    # Merge duplicate ports (same port/proto combination)
    _merge_duplicate_ports(report)

    return report


def _merge_duplicate_ports(report: ScanReport) -> None:
    """Merge duplicate port entries, keeping the most complete information."""
    if not report.ports:
        return

    # Group ports by (port, proto) key
    port_groups = {}
    for port_info in report.ports:
        key = (port_info.port, port_info.proto)
        if key not in port_groups:
            port_groups[key] = []
        port_groups[key].append(port_info)

    # Merge each group
    merged_ports = []
    for key, ports in port_groups.items():
        if len(ports) == 1:
            merged_ports.append(ports[0])
        else:
            # Merge multiple entries for the same port
            merged = _merge_port_entries(ports)
            merged_ports.append(merged)

    report.ports = merged_ports


def _merge_port_entries(ports: list) -> 'PortInfo':
    """Merge multiple PortInfo entries for the same port, keeping best data."""
    from fingerprinter.core.result import PortInfo

    # Start with first entry
    merged = PortInfo(
        port=ports[0].port,
        proto=ports[0].proto
    )

    # Merge data from all entries, preferring non-null/non-empty values
    for port in ports:
        # Prefer longer/more detailed banners
        if not merged.banner or (port.banner and len(port.banner) > len(merged.banner or "")):
            merged.banner = port.banner

        # Prefer specific service names over generic ones
        if not merged.service or (port.service and port.service != "unknown"):
            merged.service = port.service

        # Always take product/version if available
        if port.product:
            merged.product = port.product
        if port.version:
            merged.version = port.version
        if port.extrainfo:
            merged.extrainfo = port.extrainfo

        # Take confidence if higher
        if port.confidence and (not merged.confidence or port.confidence > merged.confidence):
            merged.confidence = port.confidence

        # Take method if available
        if port.method:
            merged.method = port.method

        # Prefer structured fingerprints
        if port.fingerprint:
            merged.fingerprint = port.fingerprint

        # Always take raw fingerprints
        if port.raw_fingerprint:
            merged.raw_fingerprint = port.raw_fingerprint

    return merged
