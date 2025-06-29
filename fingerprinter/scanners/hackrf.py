import asyncio
import json
import subprocess
import tempfile
import numpy as np
from datetime import datetime
from typing import List, Optional, Tuple
import os
import time
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport, RfScanInfo, FrequencyBin

# Scanner metadata
SCANNER_INFO = {
    'name': 'hackrf',
    'description': 'RF spectrum analysis using HackRF One SDR device',
    'target_types': ['*'],  # Works with any target type for context
    'capabilities': [
        'Wide spectrum scanning (1MHz - 6GHz)',
        'Hot bin detection',
        'Signal power analysis',
        'Multi-band frequency sweeps',
        'IoT device detection',
        'WiFi/Bluetooth activity detection'
    ],
    'requirements': [
        'HackRF One SDR device',
        'hackrf command-line tools',
        'Proper USB permissions (plugdev group)'
    ]
}

# Check for HackRF tools availability
def _check_hackrf_tools():
    """Check if HackRF command-line tools are available."""
    try:
        result = subprocess.run(['hackrf_info'], capture_output=True, timeout=5)
        # Tools are available if the command runs (even if no device found)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False

HACKRF_AVAILABLE = _check_hackrf_tools()

# Common frequency ranges of interest (in Hz)
FREQUENCY_RANGES = {
    'ism_433': (433.05e6, 434.79e6),      # 433 MHz ISM band
    'ism_868': (863e6, 870e6),            # 868 MHz ISM band (EU)
    'ism_915': (902e6, 928e6),            # 915 MHz ISM band (US)
    'wifi_2g4': (2.4e9, 2.5e9),          # 2.4 GHz WiFi
    'bluetooth': (2.402e9, 2.480e9),      # Bluetooth
    'wifi_5g_low': (5.15e9, 5.35e9),     # 5 GHz WiFi lower
    'wifi_5g_mid': (5.47e9, 5.725e9),    # 5 GHz WiFi middle
    'wifi_5g_high': (5.725e9, 5.875e9),  # 5 GHz WiFi upper
    'lte_700': (698e6, 798e6),            # LTE Band 12/13/14/17
    'lte_850': (824e6, 894e6),            # LTE Band 5
    'lte_1900': (1850e6, 1990e6),        # LTE Band 2/25
    'cellular_gsm': (880e6, 960e6),       # GSM 900
    'cellular_dcs': (1710e6, 1880e6),     # DCS 1800
}

# HackRF hardware limits
HACKRF_MIN_FREQ = 1e6      # 1 MHz
HACKRF_MAX_FREQ = 6e9      # 6 GHz
DEFAULT_SAMPLE_RATE = 10e6  # 10 MHz sample rate


async def scan(ctx: ScanContext, report: ScanReport, log) -> None:
    """
    Perform HackRF spectrum scanning to identify frequency activity.

    Works with any target type - the target is used for context and identification.
    For location-based targets, coordinates can be used for geographic context.
    """
    if not HACKRF_AVAILABLE:
        log.warning("HackRF tools not available. Install hackrf package and ensure device permissions.")
        log.info("On Ubuntu/Debian: sudo apt install hackrf")
        log.info("Add user to plugdev group: sudo usermod -a -G plugdev $USER")
        report.notes.append("HackRF scanning skipped: hackrf tools not available")
        return

    # Initialize console for rich output
    console = Console()

    # Log scan context
    if ctx.target_type == 'coordinates':
        console.print(f"[bold blue]🛰️  Starting HackRF spectrum analysis at coordinates {ctx.target_value}[/bold blue]")
    elif ctx.location:
        console.print(f"[bold blue]📡 Starting HackRF spectrum analysis - Target: {ctx.target_value}, Location: {ctx.location}[/bold blue]")
    else:
        console.print(f"[bold blue]📡 Starting HackRF spectrum analysis - Context: {ctx.target_value}[/bold blue]")

    try:
        # Verify HackRF device is connected
        device_available = await _verify_hackrf_device(log)
        if not device_available:
            console.print("[bold red]❌ No HackRF device detected - please connect device and ensure proper permissions[/bold red]")
            console.print("[yellow]💡 To fix: sudo usermod -a -G plugdev $USER (then logout/login)[/yellow]")
            report.notes.append("HackRF device not connected or accessible")
            return

        console.print("[bold green]✅ HackRF device detected and ready[/bold green]")

        # Scan frequency ranges for activity
        rf_results = []

        # Determine scan strategy based on target type and context
        if ctx.interactive:
            ranges_to_scan = ['wifi_2g4', 'bluetooth', 'ism_433', 'ism_915']
        elif ctx.target_type == 'coordinates':
            # For geographic targets, do comprehensive scan
            ranges_to_scan = list(FREQUENCY_RANGES.keys())
        elif ctx.target_type in ['ip', 'hostname']:
            # For network targets, focus on WiFi and IoT frequencies
            ranges_to_scan = ['wifi_2g4', 'wifi_5g_low', 'bluetooth', 'ism_433', 'ism_868', 'ism_915']
        else:
            # Default comprehensive scan
            ranges_to_scan = list(FREQUENCY_RANGES.keys())

        # Filter out ranges outside HackRF capability
        valid_ranges = []
        for range_name in ranges_to_scan:
            if range_name not in FREQUENCY_RANGES:
                continue
            freq_min, freq_max = FREQUENCY_RANGES[range_name]
            if freq_max < HACKRF_MIN_FREQ or freq_min > HACKRF_MAX_FREQ:
                continue
            valid_ranges.append(range_name)

        console.print(f"[bold cyan]🎯 Scanning {len(valid_ranges)} frequency ranges[/bold cyan]")

        # Scan each frequency range with unified progress display
        for i, range_name in enumerate(valid_ranges):
            freq_min, freq_max = FREQUENCY_RANGES[range_name]

            console.print(f"\n[bold blue]📡 [{i+1}/{len(valid_ranges)}] Scanning {range_name}: {freq_min/1e6:.1f} - {freq_max/1e6:.1f} MHz[/bold blue]")

            try:
                rf_scan = await _scan_frequency_range_with_progress(
                    range_name, freq_min, freq_max, ctx, log, console, i+1, len(valid_ranges)
                )
                if rf_scan:
                    rf_results.append(rf_scan)
                    console.print(f"[green]✅ Found {len(rf_scan.hot_bins)} active frequencies in {range_name}[/green]")

                    # Show top signals immediately
                    if rf_scan.hot_bins:
                        top_signals = sorted(rf_scan.hot_bins, key=lambda x: x.power_db, reverse=True)[:3]
                        for j, signal in enumerate(top_signals, 1):
                            freq_desc = _get_frequency_description(signal.frequency_hz)
                            console.print(f"[cyan]    {j}. {signal.frequency_hz/1e6:.3f} MHz: {signal.power_db:.1f} dB ({freq_desc})[/cyan]")
                else:
                    console.print(f"[dim]⚪ No activity detected in {range_name}[/dim]")

            except Exception as e:
                console.print(f"[red]❌ Error scanning {range_name}: {e}[/red]")
                report.notes.append(f"RF scan error ({range_name}): {str(e)}")

        # Add results to report
        report.rf_scans.extend(rf_results)

        # Display final summary
        total_hot_bins = sum(len(scan.hot_bins) for scan in rf_results)
        if total_hot_bins > 0:
            console.print(f"\n[bold green]🎉 RF scan complete: found {total_hot_bins} active frequency bins across {len(rf_results)} ranges[/bold green]")

            # Show top findings in a table
            all_bins = []
            for scan in rf_results:
                all_bins.extend(scan.hot_bins)
            all_bins.sort(key=lambda x: x.power_db, reverse=True)

            if all_bins:
                table = Table(title="🔥 Top Active Frequencies")
                table.add_column("Rank", style="cyan", no_wrap=True)
                table.add_column("Frequency", style="magenta")
                table.add_column("Power", style="green")
                table.add_column("Description", style="yellow")

                for i, bin in enumerate(all_bins[:10]):
                    freq_desc = _get_frequency_description(bin.frequency_hz)
                    table.add_row(
                        f"{i+1}",
                        f"{bin.frequency_hz/1e6:.3f} MHz",
                        f"{bin.power_db:.1f} dB",
                        freq_desc
                    )

                console.print(table)
        else:
            console.print("[yellow]🔍 RF scan complete: no significant activity detected[/yellow]")

        # Add context-specific notes
        if ctx.target_type == 'coordinates':
            report.notes.append(f"RF survey conducted at coordinates {ctx.target_value}")
        elif ctx.target_type in ['ip', 'hostname'] and total_hot_bins > 0:
            report.notes.append(f"RF environment scan for network target {ctx.target_value}")

    except Exception as e:
        console.print(f"[bold red]💥 HackRF scanning failed: {e}[/bold red]")
        report.notes.append(f"HackRF scan error: {str(e)}")


async def _verify_hackrf_device(log) -> bool:
    """Verify HackRF device is connected and accessible."""
    try:
        result = await asyncio.create_subprocess_exec(
            'hackrf_info',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0:
            info = stdout.decode('utf-8')
            if 'Found HackRF' in info:
                log.debug("HackRF device detected and accessible")
                return True

        log.error("HackRF device not found or not accessible")
        if stderr:
            log.debug(f"hackrf_info stderr: {stderr.decode('utf-8')}")
        return False

    except Exception as e:
        log.error(f"Error checking HackRF device: {e}")
        return False


async def _scan_frequency_range_with_progress(
    range_name: str, freq_min: float, freq_max: float,
    ctx: ScanContext, log, console: Console, current_range: int, total_ranges: int
) -> Optional[RfScanInfo]:
    """
    Scan a specific frequency range with live progress display and spectrum visualization.
    """
    try:
        # Calculate scan parameters
        center_freq = (freq_min + freq_max) / 2
        bandwidth = freq_max - freq_min

        # Scan duration
        scan_duration = 3.0 if ctx.interactive else 8.0

        # Use hackrf_sweep for wide spectrum scanning
        freq_min_mhz = int(freq_min / 1e6)
        freq_max_mhz = int(freq_max / 1e6)

        # Create temporary file for sweep output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.csv', delete=False) as temp_file:
            temp_filename = temp_file.name

        try:
            # Run hackrf_sweep with live progress
            cmd = [
                'hackrf_sweep',
                '-f', f"{freq_min_mhz}:{freq_max_mhz}",
                '-w', '1000000',  # 1 MHz step size for wide scan
                '-l', '32',       # LNA gain
                '-g', '30',       # VGA gain
                '-a', '1',        # Enable antenna power
                '-r', temp_filename
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Monitor the scan with simple progress updates
            start_time = time.time()
            last_update = 0
            last_progress_shown = -1

            console.print(f"    [dim]⏳ Starting {scan_duration:.1f}s scan...[/dim]")

            while process.returncode is None:
                # Check if process is still running
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.5)
                    break
                except asyncio.TimeoutError:
                    pass

                elapsed = time.time() - start_time
                if elapsed >= scan_duration:
                    process.terminate()
                    await process.wait()
                    break

                # Show progress every 20%
                progress_percent = min((elapsed / scan_duration) * 100, 100)
                progress_step = int(progress_percent // 20) * 20

                if progress_step > last_progress_shown and progress_step > 0:
                    # Create simple progress bar
                    bar_width = 30
                    filled = int((progress_percent / 100) * bar_width)
                    bar = "█" * filled + "░" * (bar_width - filled)
                    console.print(f"    [blue]Progress: {progress_percent:5.1f}% [{bar}] ({elapsed:.1f}s)[/blue]")
                    last_progress_shown = progress_step

                # Show spectrum updates every 2 seconds
                if elapsed - last_update >= 2.0:
                    spectrum_data = await _get_live_spectrum_data(temp_filename, freq_min, freq_max)
                    if spectrum_data.get('hot_bins'):
                        # Show spectrum visualization
                        ascii_spectrum = _create_ascii_spectrum(spectrum_data)
                        console.print(f"    {ascii_spectrum}")
                        hot_count = len(spectrum_data['hot_bins'])
                        console.print(f"    [green]🔥 {hot_count} active signals detected[/green]")
                    else:
                        # Show basic spectrum visualization
                        ascii_spectrum = _create_ascii_spectrum({'frequency_powers': {}})
                        console.print(f"    {ascii_spectrum}")
                    last_update = elapsed

            # Final progress
            console.print(f"    [green]✓ Scan completed in {time.time() - start_time:.1f}s[/green]")

            # Read and parse the final sweep data
            hot_bins = await _parse_sweep_data(temp_filename, freq_min, freq_max, log)

            # Calculate statistics
            if hot_bins:
                powers = [bin.power_db for bin in hot_bins]
                noise_floor = min(powers) if powers else -80.0
                detection_threshold = noise_floor + 15.0
            else:
                noise_floor = -80.0
                detection_threshold = -65.0

            return RfScanInfo(
                center_freq_hz=center_freq,
                sample_rate_hz=DEFAULT_SAMPLE_RATE,
                bandwidth_hz=bandwidth,
                gain_db=30,
                hot_bins=hot_bins,
                scan_duration_sec=scan_duration,
                total_samples=0,  # Not applicable for sweep mode
                noise_floor_db=noise_floor,
                detection_threshold_db=detection_threshold
            )

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_filename)
            except:
                pass

    except Exception as e:
        log.error(f"Error scanning frequency range {range_name}: {e}")
        return None





def _create_ascii_spectrum(spectrum_data: dict) -> str:
    """Create ASCII art spectrum visualization."""
    if not spectrum_data or not spectrum_data.get('frequency_powers'):
        # Default spectrum when no data
        return "[dim]🎵 " + "▁" * 50 + " [/dim]"

    frequency_powers = spectrum_data['frequency_powers']

    # Convert to ASCII bars
    if not frequency_powers:
        return "[dim]🎵 " + "▁" * 50 + " [/dim]"

    # Normalize power values for display
    powers = list(frequency_powers.values())
    if not powers:
        return "[dim]🎵 " + "▁" * 50 + " [/dim]"

    min_power = min(powers)
    max_power = max(powers)
    power_range = max_power - min_power if max_power != min_power else 1

    # Create ASCII spectrum
    spectrum_chars = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    spectrum_width = 50

    # Sample frequencies for display
    freq_list = sorted(frequency_powers.keys())
    if len(freq_list) > spectrum_width:
        # Downsample for display
        step = len(freq_list) // spectrum_width
        sampled_freqs = [freq_list[i * step] for i in range(spectrum_width)]
    else:
        # Pad with empty if not enough frequencies
        sampled_freqs = freq_list + [None] * (spectrum_width - len(freq_list))

    ascii_bars = []
    for freq in sampled_freqs[:spectrum_width]:
        if freq and freq in frequency_powers:
            power = frequency_powers[freq]
            normalized = (power - min_power) / power_range
            char_index = min(int(normalized * len(spectrum_chars)), len(spectrum_chars) - 1)
            char = spectrum_chars[char_index]

            # Color based on power level
            if normalized > 0.8:
                ascii_bars.append(f"[bold red]{char}[/bold red]")
            elif normalized > 0.6:
                ascii_bars.append(f"[red]{char}[/red]")
            elif normalized > 0.4:
                ascii_bars.append(f"[yellow]{char}[/yellow]")
            elif normalized > 0.2:
                ascii_bars.append(f"[green]{char}[/green]")
            else:
                ascii_bars.append(f"[dim]{char}[/dim]")
        else:
            ascii_bars.append("[dim]▁[/dim]")

    return "🎵 " + "".join(ascii_bars) + " 🎵"


async def _get_live_spectrum_data(filename: str, freq_min: float, freq_max: float) -> dict:
    """Get current spectrum data from the sweep file."""
    try:
        if not os.path.exists(filename) or os.path.getsize(filename) == 0:
            return {'frequency_powers': {}, 'hot_bins': []}

        # Read current data
        frequency_powers = {}
        with open(filename, 'r') as f:
            lines = f.readlines()

        for line in lines[-50:]:  # Only look at recent data
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('date'):
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            try:
                freq_hz = float(parts[2])
                power_db = float(parts[3])

                if freq_min <= freq_hz <= freq_max:
                    frequency_powers[freq_hz] = max(frequency_powers.get(freq_hz, -100), power_db)
            except (ValueError, IndexError):
                continue

        # Identify hot bins
        if frequency_powers:
            powers = list(frequency_powers.values())
            noise_floor = np.percentile(powers, 25) if len(powers) > 4 else min(powers)
            threshold = noise_floor + 12

            hot_bins = []
            for freq_hz, power_db in frequency_powers.items():
                if power_db > threshold:
                    hot_bins.append({
                        'frequency_hz': freq_hz,
                        'power_db': power_db
                    })

            return {
                'frequency_powers': frequency_powers,
                'hot_bins': hot_bins,
                'noise_floor': noise_floor,
                'threshold': threshold
            }

        return {'frequency_powers': {}, 'hot_bins': []}

    except Exception:
        return {'frequency_powers': {}, 'hot_bins': []}


async def _parse_sweep_data(filename: str, freq_min: float, freq_max: float, log) -> List[FrequencyBin]:
    """
    Parse hackrf_sweep CSV output and identify hot bins.
    """
    hot_bins = []

    try:
        if not os.path.exists(filename) or os.path.getsize(filename) == 0:
            log.warning("Sweep data file is empty or missing")
            return hot_bins

        # Read sweep data
        with open(filename, 'r') as f:
            lines = f.readlines()

        if len(lines) < 2:
            log.warning("Insufficient sweep data")
            return hot_bins

        # Parse CSV data (hackrf_sweep format: date, time, freq_hz, power_db, ...)
        frequency_powers = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('date'):
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            try:
                freq_hz = float(parts[2])
                power_db = float(parts[3])

                # Only consider frequencies in our target range
                if freq_min <= freq_hz <= freq_max:
                    # Keep track of maximum power seen at each frequency
                    if freq_hz not in frequency_powers or power_db > frequency_powers[freq_hz]:
                        frequency_powers[freq_hz] = power_db
            except (ValueError, IndexError):
                continue

        if not frequency_powers:
            log.debug("No valid frequency data found in sweep")
            return hot_bins

        # Calculate noise floor and threshold
        powers = list(frequency_powers.values())
        noise_floor = np.percentile(powers, 25)  # 25th percentile
        threshold = noise_floor + 12  # 12 dB above noise floor

        log.debug(f"Noise floor: {noise_floor:.1f} dB, Detection threshold: {threshold:.1f} dB")

        # Identify hot bins (frequencies with power above threshold)
        for freq_hz, power_db in frequency_powers.items():
            if power_db > threshold:
                hot_bin = FrequencyBin(
                    frequency_hz=freq_hz,
                    power_db=power_db,
                    bandwidth_hz=1e6,  # 1 MHz resolution from sweep
                    detection_method="hackrf_sweep",
                    timestamp=datetime.utcnow()
                )
                hot_bins.append(hot_bin)

        # Sort by power (strongest first) and limit results
        hot_bins.sort(key=lambda x: x.power_db, reverse=True)
        if len(hot_bins) > 25:  # Limit to top 25 signals
            hot_bins = hot_bins[:25]

        log.debug(f"Identified {len(hot_bins)} hot bins above {threshold:.1f} dB")

    except Exception as e:
        log.error(f"Error parsing sweep data: {e}")

    return hot_bins


async def _scan_frequency_range(
    range_name: str, freq_min: float, freq_max: float,
    ctx: ScanContext, log
) -> Optional[RfScanInfo]:
    """
    Original scan function without progress display (for backward compatibility).
    """
    console = Console()
    return await _scan_frequency_range_with_progress(
        range_name, freq_min, freq_max, ctx, log, console, 1, 1
    )


async def _collect_iq_samples(center_freq: float, sample_rate: float, duration: float, log) -> Optional[np.ndarray]:
    """
    Collect IQ samples using hackrf_transfer for detailed analysis.
    This is for future detailed fingerprinting of identified hot bins.
    """
    try:
        num_samples = int(duration * sample_rate * 2)  # I and Q samples

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as temp_file:
            temp_filename = temp_file.name

        try:
            # Use hackrf_transfer to collect samples
            cmd = [
                'hackrf_transfer',
                '-r', temp_filename,
                '-f', str(int(center_freq)),
                '-s', str(int(sample_rate)),
                '-l', '32',  # LNA gain
                '-g', '30',  # VGA gain
                '-a', '1',   # Enable antenna power
                '-n', str(num_samples)
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(process.wait(), timeout=duration + 5.0)

            # Read binary IQ data
            if os.path.exists(temp_filename) and os.path.getsize(temp_filename) > 0:
                with open(temp_filename, 'rb') as f:
                    raw_data = f.read()

                # Convert to complex IQ samples
                samples = np.frombuffer(raw_data, dtype=np.int8)
                i_samples = samples[0::2].astype(np.float32) / 128.0
                q_samples = samples[1::2].astype(np.float32) / 128.0
                iq_samples = i_samples + 1j * q_samples

                log.debug(f"Collected {len(iq_samples)} IQ samples")
                return iq_samples

        finally:
            try:
                os.unlink(temp_filename)
            except:
                pass

    except Exception as e:
        log.error(f"Error collecting IQ samples: {e}")

    return None


def _get_frequency_description(freq_hz: float) -> str:
    """
    Get a human-readable description of what might be using a frequency.
    """
    freq_mhz = freq_hz / 1e6

    # WiFi channels
    if 2400 <= freq_mhz <= 2500:
        if 2412 <= freq_mhz <= 2484:
            channel = int((freq_mhz - 2412) / 5) + 1
            if channel <= 13:
                return f"WiFi Channel {channel}"
        return "WiFi 2.4GHz"

    if 5150 <= freq_mhz <= 5875:
        if 5170 <= freq_mhz <= 5330:
            return "WiFi 5GHz (Lower)"
        elif 5490 <= freq_mhz <= 5710:
            return "WiFi 5GHz (Middle)"
        elif 5735 <= freq_mhz <= 5875:
            return "WiFi 5GHz (Upper)"
        return "WiFi 5GHz"

    # Bluetooth
    if 2402 <= freq_mhz <= 2480:
        return "Bluetooth"

    # ISM bands
    if 433.05 <= freq_mhz <= 434.79:
        return "433MHz IoT Device"

    if 863 <= freq_mhz <= 870:
        return "868MHz IoT Device (EU)"

    if 902 <= freq_mhz <= 928:
        return "915MHz IoT Device (US)"

    # Cellular
    if 698 <= freq_mhz <= 798:
        return "LTE Band 12/13/14/17"

    if 824 <= freq_mhz <= 894:
        return "LTE Band 5 (850MHz)"

    if 1850 <= freq_mhz <= 1990:
        return "LTE Band 2/25 (1900MHz)"

    if 880 <= freq_mhz <= 960:
        return "GSM 900"

    if 1710 <= freq_mhz <= 1880:
        return "DCS 1800"

    # Generic frequency ranges
    if freq_mhz < 30:
        return "HF"
    elif freq_mhz < 300:
        return "VHF"
    elif freq_mhz < 3000:
        return "UHF"
    else:
        return "Microwave"
