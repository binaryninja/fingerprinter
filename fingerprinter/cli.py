import argparse
from typing import Optional

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fingerprinter",
        description="Modular async fingerprinting tool with comprehensive detection capabilities"
    )

    # Target specification
    p.add_argument(
        "target",
        help="Target to scan (IP address, hostname, coordinates, identifier, etc.)"
    )

    # Target context
    p.add_argument(
        "--target-type",
        choices=['ip', 'hostname', 'url', 'mac', 'bluetooth', 'coordinates', 'file', 'identifier'],
        help="Override automatic target type detection"
    )

    p.add_argument(
        "--location",
        help="Physical location context (e.g., 'Home Lab', 'Office Floor 2')"
    )

    p.add_argument(
        "--scan-id",
        help="Custom scan identifier (auto-generated if not provided)"
    )

    p.add_argument(
        "--note",
        action="append",
        dest="notes",
        help="Add context notes (can be used multiple times)"
    )

    # Scanner selection
    p.add_argument(
        "-m", "--module",
        action="append",
        help="Specific scanner modules to run (can be used multiple times)"
    )

    p.add_argument(
        "--exclude-module",
        action="append",
        help="Scanner modules to exclude (can be used multiple times)"
    )

    # Output options
    p.add_argument(
        "--json-out",
        help="Write raw JSON results to file"
    )

    p.add_argument(
        "--no-markdown",
        action="store_true",
        help="Skip markdown report generation"
    )

    # Scan behavior
    p.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive menu"
    )

    p.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Scanner timeout in seconds (default: 3.0)"
    )

    p.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan mode (reduced coverage for faster results)"
    )

    # Legal acknowledgment
    p.add_argument(
        "--legal-ok",
        action="store_true",
        help="Affirm that you have legal authorization to scan the target"
    )

    # Verbosity
    p.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for info, -vv for debug)"
    )

    # Compatibility options
    p.add_argument(
        "--legacy-ip-mode",
        action="store_true",
        help="Force legacy IP-only mode for backward compatibility"
    )

    return p


def validate_args(args) -> tuple[bool, Optional[str]]:
    """
    Validate command line arguments and return (is_valid, error_message).
    """
    # Legal acknowledgment is always required
    if not args.legal_ok:
        return False, "Legal acknowledgment required. Use --legal-ok to confirm authorization."

    # Validate target format based on type
    if args.target_type == 'coordinates':
        if ',' not in args.target:
            return False, "Coordinates target must be in format 'lat,lon' (e.g., '37.7749,-122.4194')"

        try:
            parts = args.target.split(',')
            if len(parts) != 2:
                raise ValueError("Must have exactly 2 parts")
            float(parts[0])  # latitude
            float(parts[1])  # longitude
        except (ValueError, IndexError):
            return False, "Invalid coordinates format. Use 'latitude,longitude' (e.g., '37.7749,-122.4194')"

    # Validate module specifications
    if args.module and args.exclude_module:
        if set(args.module) & set(args.exclude_module):
            return False, "Cannot both include and exclude the same module"

    # Validate timeout
    if args.timeout <= 0:
        return False, "Timeout must be positive"

    return True, None


def print_usage_examples():
    """Print usage examples for different target types."""
    examples = [
        "# Network targets",
        "fingerprinter --legal-ok 192.168.1.1",
        "fingerprinter --legal-ok example.com",
        "fingerprinter --legal-ok https://example.com",
        "",
        "# RF spectrum scanning",
        "fingerprinter --legal-ok rf-survey --location 'Home Lab'",
        "fingerprinter --legal-ok 37.7749,-122.4194 --target-type coordinates",
        "",
        "# Device-specific scanning",
        "fingerprinter --legal-ok AA:BB:CC:DD:EE:FF --target-type mac",
        "",
        "# Contextual scanning",
        "fingerprinter --legal-ok 192.168.1.1 --location 'Office' --note 'Router investigation'",
        "",
        "# Scanner selection",
        "fingerprinter --legal-ok 192.168.1.1 -m nmap -m http",
        "fingerprinter --legal-ok rf-survey -m hackrf --location 'Parking Lot'",
        "",
        "# Output options",
        "fingerprinter --legal-ok 192.168.1.1 --json-out results.json --no-markdown",
    ]

    print("Usage Examples:")
    print("=" * 50)
    for example in examples:
        print(example)


def create_scan_context_from_args(args):
    """
    Create a ScanContext object from parsed command line arguments.
    """
    from fingerprinter.core.context import ScanContext, ScanTarget

    # Create target with optional type override
    if args.target_type:
        target = ScanTarget(args.target, target_type=args.target_type)
    else:
        target = ScanTarget(args.target)

    # Handle legacy IP mode
    if args.legacy_ip_mode and not target.is_ip:
        raise ValueError(f"Legacy IP mode requires an IP address, got {target.target_type}: {target.value}")

    # Create context
    context_kwargs = {
        'target': target,
        'timeout': args.timeout,
        'interactive': args.interactive,
        'legal_ok': args.legal_ok,
    }

    if args.scan_id:
        context_kwargs['scan_id'] = args.scan_id

    if args.location:
        context_kwargs['location'] = args.location

    if args.notes:
        context_kwargs['notes'] = args.notes

    return ScanContext(**context_kwargs)


def filter_compatible_scanners(scanners: list[str], context) -> tuple[list[str], list[str]]:
    """
    Filter scanners based on target compatibility.
    Returns (compatible_scanners, incompatible_scanners).
    """
    compatible = []
    incompatible = []

    for scanner in scanners:
        if context.supports_scanner(scanner):
            compatible.append(scanner)
        else:
            incompatible.append(scanner)

    return compatible, incompatible
