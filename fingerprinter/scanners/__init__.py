import importlib
import pkgutil
import asyncio
from datetime import datetime
from typing import Iterable, Optional
from fingerprinter.core.result import ScanReport
from fingerprinter.core.context import ScanContext

mods = [m.name for m in pkgutil.iter_modules(__path__) if m.name != "__init__"]

def available() -> list[str]:
    """Get list of available scanner modules."""
    return mods

async def run_scanners(ctx: ScanContext,
                       scanners_to_run: Iterable[str] | None,
                       log) -> ScanReport:
    """
    Run specified scanners against the target.

    Args:
        ctx: Scan context with target and configuration
        scanners_to_run: List of scanner names to run, or None for all compatible
        log: Logger instance

    Returns:
        ScanReport with results from all scanners
    """
    # Create report with enhanced target information
    report = ScanReport(
        target=ctx.target_value,
        target_type=ctx.target_type,
        scan_id=ctx.scan_id,
        started=ctx.start,
        location=ctx.location,
        context_notes=ctx.notes.copy() if ctx.notes else []
    )

    log.info(f"Scan initialized: {report.get_context_summary()}")

    async def _run_scanner(name: str):
        """Run a single scanner module."""
        if scanners_to_run and name not in scanners_to_run:
            return

        # Check compatibility
        if not ctx.supports_scanner(name):
            log.debug(f"Skipping {name}: incompatible with {ctx.target_type} target")
            return

        log.info(f"Starting {name} scanner")
        start_time = datetime.utcnow()

        try:
            mod = importlib.import_module(f".{name}", package=__package__)
            if not hasattr(mod, "scan"):
                log.warning(f"Scanner {name} has no .scan() function")
                report.notes.append(f"Scanner {name}: missing scan function")
                return

            # Run the scanner
            await mod.scan(ctx, report, log)

            duration = (datetime.utcnow() - start_time).total_seconds()
            log.info(f"Scanner {name} completed in {duration:.1f}s")

        except Exception as exc:
            duration = (datetime.utcnow() - start_time).total_seconds()
            log.exception(f"Scanner '{name}' failed after {duration:.1f}s: {exc}")
            report.notes.append(f"Scanner {name} error: {str(exc)}")

    # Determine which scanners to run
    if scanners_to_run is None:
        # Run all available compatible scanners
        compatible_scanners = [name for name in mods if ctx.supports_scanner(name)]
        log.info(f"Auto-selected compatible scanners: {', '.join(compatible_scanners)}")
        await asyncio.gather(*[_run_scanner(name) for name in compatible_scanners])
    else:
        # Run specified scanners
        await asyncio.gather(*[_run_scanner(name) for name in scanners_to_run])

    report.finished = datetime.utcnow()

    # Post-process results
    _merge_duplicate_ports(report)
    _add_scan_metadata(report, ctx, log)

    total_duration = (report.finished - report.started).total_seconds()
    log.info(f"Scan completed in {total_duration:.1f}s")

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


def _add_scan_metadata(report: ScanReport, ctx: ScanContext, log) -> None:
    """Add metadata and summary information to the scan report."""

    # Add target type information
    if ctx.target_type != 'ip':
        report.notes.append(f"Target type: {ctx.target_type}")

    # Add location context
    if ctx.location and ctx.location not in report.notes:
        report.notes.append(f"Scan location: {ctx.location}")

    # Add scan statistics
    if report.ports:
        tcp_ports = len([p for p in report.ports if p.proto == 'tcp'])
        udp_ports = len([p for p in report.ports if p.proto == 'udp'])
        if tcp_ports and udp_ports:
            report.notes.append(f"Ports discovered: {tcp_ports} TCP, {udp_ports} UDP")
        elif tcp_ports:
            report.notes.append(f"Ports discovered: {tcp_ports} TCP")
        elif udp_ports:
            report.notes.append(f"Ports discovered: {udp_ports} UDP")

    # Add RF statistics
    if report.rf_scans:
        total_hot_bins = sum(len(scan.hot_bins) for scan in report.rf_scans)
        frequency_ranges = len(report.rf_scans)
        if total_hot_bins > 0:
            report.notes.append(f"RF activity: {total_hot_bins} active frequencies across {frequency_ranges} ranges")

    # Add HTTP service summary
    if report.http:
        status_counts = {}
        for http_info in report.http:
            status = http_info.status
            status_counts[status] = status_counts.get(status, 0) + 1

        status_summary = ", ".join([f"{count}×{status}" for status, count in sorted(status_counts.items())])
        report.notes.append(f"HTTP services: {len(report.http)} endpoints ({status_summary})")


def get_scanner_info(scanner_name: str) -> dict:
    """Get information about a specific scanner module."""
    try:
        mod = importlib.import_module(f".{scanner_name}", package=__package__)

        info = {
            'name': scanner_name,
            'available': True,
            'has_scan_function': hasattr(mod, 'scan'),
            'description': getattr(mod, '__doc__', 'No description available'),
        }

        # Try to get additional metadata
        if hasattr(mod, 'SCANNER_INFO'):
            info.update(mod.SCANNER_INFO)

        return info

    except ImportError as e:
        return {
            'name': scanner_name,
            'available': False,
            'error': str(e),
            'description': 'Module import failed'
        }


def list_scanners() -> dict:
    """Get detailed information about all available scanners."""
    scanner_info = {}

    for scanner_name in available():
        scanner_info[scanner_name] = get_scanner_info(scanner_name)

    return scanner_info


def validate_scanner_compatibility(scanner_names: list[str], target_type: str) -> dict:
    """
    Validate scanner compatibility with a target type.

    Returns:
        {
            'compatible': [list of compatible scanner names],
            'incompatible': [list of incompatible scanner names],
            'unknown': [list of scanner names that couldn't be checked]
        }
    """
    from fingerprinter.core.context import ScanTarget

    # Create a dummy target for compatibility checking
    dummy_target = ScanTarget("dummy", target_type=target_type)
    dummy_ctx = type('DummyContext', (), {
        'target': dummy_target,
        'target_type': target_type,
        'supports_scanner': lambda self, scanner: dummy_target.target_type in {
            'nmap': ['ip', 'hostname'],
            'http': ['ip', 'hostname', 'url'],
            'port': ['ip', 'hostname'],
            'arp': ['ip'],
            'hackrf': ['*'],
            'bluetooth': ['bluetooth', 'mac', '*'],
            'wifi': ['*'],
            'gps': ['coordinates', '*'],
            'file': ['file'],
        }.get(scanner, ['*'])
    })()

    result = {
        'compatible': [],
        'incompatible': [],
        'unknown': []
    }

    for scanner_name in scanner_names:
        try:
            if dummy_ctx.supports_scanner(scanner_name):
                result['compatible'].append(scanner_name)
            else:
                result['incompatible'].append(scanner_name)
        except Exception:
            result['unknown'].append(scanner_name)

    return result
