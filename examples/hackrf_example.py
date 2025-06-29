#!/usr/bin/env python3
"""
HackRF Scanner Usage Examples

This script demonstrates how to use the HackRF scanner module
for RF spectrum analysis and device fingerprinting.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path so we can import fingerprinter modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport
from fingerprinter.scanners.hackrf import scan as hackrf_scan


class MockLogger:
    """Simple logger for examples."""
    def info(self, msg): print(f"INFO: {msg}")
    def warning(self, msg): print(f"WARNING: {msg}")
    def error(self, msg): print(f"ERROR: {msg}")
    def debug(self, msg): print(f"DEBUG: {msg}")


async def example_basic_rf_scan():
    """Example: Basic HackRF RF spectrum scan."""
    print("=== Basic HackRF RF Scan Example ===")
    print()

    # Create scan context
    ctx = ScanContext(
        target="192.168.1.1",
        timeout=5.0,
        interactive=False,
        legal_ok=True
    )

    # Create scan report
    report = ScanReport(target=ctx.target, started=ctx.start)

    # Create logger
    log = MockLogger()

    print(f"Scanning target: {ctx.target}")
    print("This will scan common frequency ranges for RF activity...")
    print()

    # Run HackRF scan
    await hackrf_scan(ctx, report, log)

    # Display results
    if report.rf_scans:
        print("\n=== RF Scan Results ===")
        total_hot_bins = sum(len(scan.hot_bins) for scan in report.rf_scans)
        print(f"Found {total_hot_bins} active frequency bins across {len(report.rf_scans)} bands")

        # Show each band's results
        for i, rf_scan in enumerate(report.rf_scans):
            center_mhz = rf_scan.center_freq_hz / 1e6
            bw_mhz = rf_scan.bandwidth_hz / 1e6
            print(f"\nBand {i+1}: {center_mhz:.1f} MHz (±{bw_mhz/2:.1f} MHz)")
            print(f"  Noise floor: {rf_scan.noise_floor_db:.1f} dB")
            print(f"  Hot bins: {len(rf_scan.hot_bins)}")

            for bin in rf_scan.hot_bins[:5]:  # Show top 5
                freq_mhz = bin.frequency_hz / 1e6
                print(f"    {freq_mhz:8.3f} MHz: {bin.power_db:6.1f} dB")

    else:
        print("No RF scan results (device not connected or available)")

    return report


async def example_interactive_rf_scan():
    """Example: Interactive HackRF scan with reduced frequency ranges."""
    print("\n=== Interactive HackRF RF Scan Example ===")
    print()

    # Create scan context for interactive mode
    ctx = ScanContext(
        target="192.168.1.100",
        timeout=3.0,
        interactive=True,  # This reduces scan time and frequency ranges
        legal_ok=True
    )

    # Create scan report
    report = ScanReport(target=ctx.target, started=ctx.start)

    # Create logger
    log = MockLogger()

    print(f"Interactive scan of target: {ctx.target}")
    print("This will perform a quick scan of WiFi and common IoT frequencies...")
    print()

    # Run HackRF scan
    await hackrf_scan(ctx, report, log)

    # Analyze and categorize results
    if report.rf_scans:
        print("\n=== Signal Analysis ===")

        all_bins = []
        for scan in report.rf_scans:
            all_bins.extend(scan.hot_bins)

        # Sort by power level
        all_bins.sort(key=lambda x: x.power_db, reverse=True)

        # Categorize signals
        wifi_signals = []
        iot_signals = []
        cellular_signals = []
        unknown_signals = []

        for bin in all_bins:
            freq_hz = bin.frequency_hz

            if 2400e6 <= freq_hz <= 2500e6:
                # WiFi 2.4GHz analysis
                wifi_channels = {
                    2412e6: 1, 2417e6: 2, 2422e6: 3, 2427e6: 4, 2432e6: 5,
                    2437e6: 6, 2442e6: 7, 2447e6: 8, 2452e6: 9, 2457e6: 10,
                    2462e6: 11, 2467e6: 12, 2472e6: 13, 2484e6: 14
                }
                closest_freq = min(wifi_channels.keys(), key=lambda x: abs(x - freq_hz))
                if abs(closest_freq - freq_hz) < 5e6:
                    channel = wifi_channels[closest_freq]
                    wifi_signals.append((bin, f"WiFi Channel {channel}"))
                else:
                    wifi_signals.append((bin, "2.4GHz WiFi/Bluetooth"))

            elif 5000e6 <= freq_hz <= 6000e6:
                wifi_signals.append((bin, "5GHz WiFi"))

            elif 430e6 <= freq_hz <= 440e6:
                iot_signals.append((bin, "433MHz IoT/Remote"))

            elif 860e6 <= freq_hz <= 870e6:
                iot_signals.append((bin, "868MHz IoT (EU)"))

            elif 900e6 <= freq_hz <= 930e6:
                iot_signals.append((bin, "915MHz IoT (US)"))

            elif 800e6 <= freq_hz <= 2000e6:
                cellular_signals.append((bin, "Cellular/LTE"))

            else:
                unknown_signals.append((bin, "Unknown"))

        # Display categorized results
        categories = [
            ("WiFi Networks", wifi_signals),
            ("IoT Devices", iot_signals),
            ("Cellular Signals", cellular_signals),
            ("Unknown Signals", unknown_signals)
        ]

        for category_name, signals in categories:
            if signals:
                print(f"\n{category_name}:")
                for bin, description in signals:
                    freq_mhz = bin.frequency_hz / 1e6
                    print(f"  {freq_mhz:8.3f} MHz ({bin.power_db:6.1f} dB): {description}")

    return report


async def example_json_output():
    """Example: Generate JSON output with RF scan results."""
    print("\n=== JSON Output Example ===")
    print()

    # Run a basic scan
    report = await example_basic_rf_scan()

    # Convert to JSON
    json_data = report.asdict()

    print("\nJSON Output (RF scans section):")
    if 'rf_scans' in json_data and json_data['rf_scans']:
        print(json.dumps({'rf_scans': json_data['rf_scans']}, indent=2, default=str))
    else:
        print("No RF scan data available (simulated output):")
        sample_rf_data = {
            "rf_scans": [
                {
                    "center_freq_hz": 2450000000.0,
                    "sample_rate_hz": 10000000.0,
                    "bandwidth_hz": 100000000.0,
                    "gain_db": 30,
                    "hot_bins": [
                        {
                            "frequency_hz": 2437000000.0,
                            "power_db": -42.3,
                            "bandwidth_hz": 1000000.0,
                            "detection_method": "hackrf_sweep",
                            "timestamp": "2025-06-29T12:00:00"
                        }
                    ],
                    "scan_duration_sec": 8.0,
                    "total_samples": 0,
                    "noise_floor_db": -75.5,
                    "detection_threshold_db": -63.5
                }
            ]
        }
        print(json.dumps(sample_rf_data, indent=2))


def print_device_setup_info():
    """Print HackRF device setup information."""
    print("=== HackRF Device Setup ===")
    print()
    print("Hardware Requirements:")
    print("- HackRF One SDR device")
    print("- Appropriate antenna for target frequencies")
    print("- USB connection to computer")
    print()
    print("Software Setup:")
    print("1. Install HackRF tools:")
    print("   Ubuntu/Debian: sudo apt install hackrf")
    print("   Or build from source: https://github.com/mossmann/hackrf")
    print()
    print("2. Set up permissions:")
    print("   sudo usermod -a -G plugdev $USER")
    print("   (Then logout and login again)")
    print()
    print("3. Verify device:")
    print("   hackrf_info")
    print()
    print("Common Issues:")
    print("- 'No HackRF boards found': Check USB connection and permissions")
    print("- Permission denied: Add user to plugdev group and restart")
    print("- Poor signal quality: Use appropriate antenna and check positioning")
    print()


async def main():
    """Run all HackRF scanner examples."""
    print("HackRF Scanner Examples")
    print("======================")
    print()
    print("This script demonstrates the HackRF scanner functionality.")
    print("The scanner identifies 'hot bins' - frequencies with significant RF activity.")
    print()

    # Print setup info
    print_device_setup_info()

    # Check if HackRF tools are available
    import subprocess
    try:
        result = subprocess.run(['hackrf_info'], capture_output=True, timeout=5)
        if result.returncode == 0 and b'Found HackRF' in result.stdout:
            print("✅ HackRF device detected and ready!")
        else:
            print("⚠️  HackRF tools available but no device detected")
            print("   Examples will show expected behavior when device is connected")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ HackRF tools not installed")
        print("   Install with: sudo apt install hackrf")

    print("\n" + "="*60)

    # Run examples
    try:
        # Basic RF scan
        await example_basic_rf_scan()

        # Interactive RF scan
        await example_interactive_rf_scan()

        # JSON output
        await example_json_output()

        print("\n=== Usage in Fingerprinter Tool ===")
        print()
        print("Command line usage:")
        print("# Full scan including RF analysis")
        print("python -m fingerprinter --legal-ok 192.168.1.1")
        print()
        print("# RF scanning only")
        print("python -m fingerprinter --legal-ok -m hackrf 192.168.1.1")
        print()
        print("# Quick interactive RF scan")
        print("python -m fingerprinter --legal-ok --interactive -m hackrf 192.168.1.1")
        print()
        print("# Save results to JSON")
        print("python -m fingerprinter --legal-ok --json-out rf_results.json 192.168.1.1")

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nError during scan: {e}")
        print("This is expected if no HackRF device is connected")


if __name__ == "__main__":
    asyncio.run(main())
