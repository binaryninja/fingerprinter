# Fingerprinter

A modular async fingerprinting tool supporting multiple target types including IP addresses, RF spectrum analysis, coordinates, and general identifiers with comprehensive service detection and raw fingerprint retention.

## Features

- **Multi-Target Support**: Network targets (IP, hostname, URL), RF spectrum analysis, coordinates, device identifiers
- **Multi-Scanner Architecture**: Modular design with ARP, HTTP, nmap, port, and HackRF scanners
- **Automatic Target Detection**: Intelligent target type detection with manual override options
- **Context-Aware Scanning**: Location, notes, and environmental context tracking
- **Raw Fingerprint Retention**: Captures and stores nmap raw fingerprints for unrecognized services
- **Comprehensive Service Detection**: Deep service identification with version detection
- **RF Spectrum Analysis**: Wide-band frequency scanning and hot bin detection
- **Multiple Output Formats**: JSON data output and enhanced markdown reports
- **Async Performance**: Non-blocking concurrent scanning
- **Smart Scanner Selection**: Automatic compatibility-based scanner selection

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd fingerprinter

# Install dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

## Requirements

- Python 3.9+
- nmap (for service detection and fingerprinting)
- Dependencies: rich, psutil, aiohttp, requests, cryptography, numpy, scipy
- Optional: HackRF One SDR device and hackrf command-line tools for RF scanning

## Usage

### Basic Scanning

```bash
# Network scanning (traditional)
python -m fingerprinter --legal-ok 192.168.1.1

# RF spectrum survey
python -m fingerprinter --legal-ok rf-survey --location 'Home Lab'

# Coordinates-based scanning
python -m fingerprinter --legal-ok 37.7749,-122.4194 --target-type coordinates

# Verbose output
python -m fingerprinter --legal-ok 192.168.1.1 -vv

# Interactive mode
python -m fingerprinter --legal-ok rf-survey --interactive --location 'Lab'

# Specific scanners only
python -m fingerprinter --legal-ok 192.168.1.1 -m nmap -m http

# Custom JSON output file
python -m fingerprinter --legal-ok 192.168.1.1 --json-out results.json

# Show usage examples
python -m fingerprinter examples
```

### Command Line Options

- `target`: Target to scan (IP address, hostname, coordinates, identifier, etc.)
- `--target-type`: Override automatic target type detection
- `--location`: Physical location context (e.g., 'Home Lab', 'Office Floor 2')
- `--note`: Add context notes (can be used multiple times)
- `--legal-ok`: Required acknowledgment of legal authorization
- `-m, --module`: Specific scanner modules to run (can be used multiple times)
- `--exclude-module`: Scanner modules to exclude
- `--json-out`: Custom path for JSON output file
- `--no-markdown`: Skip markdown report generation
- `--interactive`: Enable interactive menu
- `--timeout`: Scanner timeout in seconds
- `--quick`: Quick scan mode for faster results
- `-v, --verbose`: Increase verbosity (use `-vv` for debug output)

## Scanner Modules

### 1. nmap Scanner
- **Service Version Detection**: Uses `nmap -sV` with maximum intensity
- **Raw Fingerprint Capture**: Automatically captures and stores nmap raw fingerprints
- **OS Detection**: Extracts operating system information
- **Comprehensive Coverage**: Scans default top 1000 ports

### 2. HTTP Scanner
- **Web Service Discovery**: Detects HTTP/HTTPS services on common ports
- **Technology Fingerprinting**: Identifies CMS, frameworks, and technologies
- **Device Signatures**: Recognizes router and device management interfaces
- **Title and Header Analysis**: Extracts page titles and server headers

### 3. Port Scanner
- **TCP Port Scanning**: Fast connection-based port discovery
- **UDP Port Scanning**: Limited UDP service detection
- **Banner Grabbing**: Captures service banners and responses
- **Service Classification**: Basic service identification by port and banner

### 4. ARP Scanner
- **MAC Address Discovery**: Retrieves hardware addresses for local networks
- **Network Validation**: Only operates on local/private network ranges
- **Multiple Methods**: Uses both `arp` and `ip neighbor` commands

### 5. HackRF Scanner (RF Spectrum Analysis)
- **Universal Target Support**: Works with any target type for context (IP, coordinates, identifiers)
- **Wide Spectrum Scanning**: Covers ISM bands (433MHz, 868MHz, 915MHz) and WiFi (2.4GHz, 5GHz)
- **Hot Bin Detection**: Identifies active frequency ranges with significant RF activity
- **Signal Power Analysis**: Measures signal strength and noise floor across frequency bands
- **Device Fingerprinting**: Detects IoT devices, WiFi networks, Bluetooth activity, and cellular signals
- **Location-Aware**: Supports coordinate-based and location-context RF surveys
- **Prerequisites**: Requires HackRF One device and hackrf command-line tools

## Output Formats

### JSON Output
Complete structured data including:
- **Target information** with type detection and context
- **Scan metadata** with unique IDs, location, and notes
- Port information with banners and service details
- **Raw fingerprints** for unrecognized services
- HTTP service details with technology signatures
- **RF scan results** with hot bins and signal analysis
- Network and OS information
- Enhanced scan timing and duration

### Markdown Reports
Human-readable reports featuring:
- **Target-specific formatting** based on scan type
- **Context information** including location and notes
- Open ports with detailed service descriptions
- Raw fingerprint display for unknown services
- Web services with status codes and technology signatures
- **RF activity summary** with frequency identification and signal analysis
- **Security assessments** for network targets
- Enhanced scan metadata and findings

## Raw Fingerprint Feature

When nmap encounters services it cannot identify, it generates raw fingerprints containing actual probe responses. This tool automatically:

1. **Captures** raw fingerprints during nmap scans
2. **Associates** fingerprints with specific ports
3. **Stores** complete fingerprint data in JSON output
4. **Displays** fingerprints in markdown reports

### Example Raw Fingerprint

```
SF-Port80-TCP:V=7.94SVN%I=9%D=6/28%Time=686054D1%P=x86_64-pc-linux-gnu%r(GetRequest,3E7,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nCache-Control:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate,\x20value\r\nContent-Length:\x20744...
```

These fingerprints are invaluable for:
- Manual service identification
- Contributing new signatures to nmap
- Security research and analysis
- Understanding service behavior

## Examples

### Multi-Target Scanning Examples

```bash
# Network device with context
python -m fingerprinter --legal-ok 192.168.1.1 \
  --location 'Home Office' \
  --note 'Monthly security audit' -vv

# RF spectrum survey
python -m fingerprinter --legal-ok rf-weekly-check \
  --location 'Data Center' \
  --note 'Interference monitoring'

# Geographic RF analysis
python -m fingerprinter --legal-ok 37.7749,-122.4194 \
  --target-type coordinates \
  --location 'Golden Gate Park'

# Combined network + RF analysis
python -m fingerprinter --legal-ok 192.168.1.1 \
  --location 'IoT Lab' \
  --note 'Smart device investigation'
```

### JSON Output Structure

```json
{
  "target": "192.168.1.1",
  "target_type": "ip",
  "scan_id": "192.168.1.1_20250629_120000",
  "started": "2025-06-28T20:46:27.937929",
  "finished": "2025-06-28T20:52:21.651566",
  "location": "Home Lab",
  "context_notes": ["Monthly security audit"],
  "ports": [
    {
      "port": 80,
      "proto": "tcp",
      "banner": "HTTP/1.0 200 OK",
      "service": "http",
      "product": "lighttpd",
      "version": "1.4.59",
      "raw_fingerprint": "SF-Port80-TCP:V=7.94SVN%I=9..."
    }
  ],
  "http": [
    {
      "url": "http://192.168.1.1:80",
      "status": 200,
      "title": "Router Management",
      "signatures": ["lighttpd", "Router Interface"]
    }
  ],
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
      "noise_floor_db": -75.5,
      "detection_threshold_db": -63.5
    }
  ],
  "notes": [
    "Target type: ip",
    "Scan location: Home Lab", 
    "Ports discovered: 3 TCP",
    "RF activity: 1 active frequencies across 1 ranges",
    "OS detected: Linux",
    "Device: Router Interface"
}
```

## Development

### Project Structure

```
fingerprinter/
├── __init__.py
├── __main__.py          # Main entry point
├── cli.py               # Command line interface
├── core/
│   ├── context.py       # Scan configuration
│   ├── result.py        # Data structures
│   └── logging.py       # Logging setup
├── scanners/
│   ├── __init__.py      # Scanner orchestration
│   ├── nmap.py          # nmap integration
│   ├── http.py          # HTTP scanning
│   ├── port.py          # Port scanning
│   ├── arp.py           # ARP scanning
│   └── hackrf.py        # RF spectrum analysis
└── report/
    └── md.py            # Markdown reporting
```

### Adding New Scanners

1. Create scanner module in `fingerprinter/scanners/`
2. Implement `async def scan(ctx, report, log)` function
3. Scanner will be automatically discovered and executed

### Key Classes

- `ScanContext`: Scan configuration and target information
- `ScanReport`: Complete scan results container
- `PortInfo`: Individual port/service information with raw fingerprints
- `HttpInfo`: HTTP service details and signatures

## HackRF RF Scanning Setup

### Hardware Requirements
- **HackRF One** SDR device
- Appropriate **antenna** for target frequency ranges
- USB connection to host computer

### Software Installation

```bash
# Install HackRF command-line tools
# Ubuntu/Debian:
sudo apt install hackrf

# Set up device permissions
sudo usermod -a -G plugdev $USER
# Then logout and login again

# Verify device connection
hackrf_info
```

### RF Scanning Usage

```bash
# Include RF scanning in full scan
python -m fingerprinter --legal-ok 192.168.1.1

# RF scanning only
python -m fingerprinter --legal-ok -m hackrf 192.168.1.1

# Quick RF scan (interactive mode)
python -m fingerprinter --legal-ok --interactive -m hackrf 192.168.1.1
```

### Frequency Ranges Scanned

- **433MHz ISM**: IoT devices, remote controls, sensors
- **868MHz ISM**: European IoT devices 
- **915MHz ISM**: US IoT devices, LoRa, Zigbee
- **2.4GHz WiFi**: WiFi networks, Bluetooth devices
- **5GHz WiFi**: Modern WiFi networks
- **Cellular bands**: LTE, GSM signals

### RF Output Example

```
INFO     Starting HackRF spectrum analysis
INFO     Scanning wifi_2g4: 2400.0 - 2500.0 MHz
INFO     Found 3 active frequencies in wifi_2g4
INFO     Top active frequencies:
INFO       1. 2437.000 MHz: -42.3 dB (WiFi Channel 6)
INFO       2. 2462.000 MHz: -45.1 dB (WiFi Channel 11)
INFO       3. 433.920 MHz: -55.8 dB (433MHz IoT Device)
```

## Legal and Ethical Use

⚠️ **Important**: This tool requires `--legal-ok` flag acknowledgment. Only use on:
- Networks you own or have explicit permission to scan
- Systems where you have proper authorization
- Environments where security testing is approved

Unauthorized scanning may violate laws and regulations.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v0.2.0 (Latest)
- ✅ **Raw Fingerprint Retention**: Complete nmap raw fingerprint capture and storage
- ✅ **Port Deduplication**: Intelligent merging of results from multiple scanners
- ✅ **Enhanced HTTP Scanner**: Technology detection and device signatures
- ✅ **Improved nmap Integration**: Better service detection and timeout handling
- ✅ **Complete Scanner Suite**: ARP, HTTP, port, and nmap scanners

### v0.1.0
- Initial release with basic nmap integration
- JSON and markdown output support
- Modular scanner architecture

## TODO

- [x] Add support for HackRF frequency scanning and hot bin detection
- [ ] Interactive mode implementation
- [ ] Raw fingerprint analysis and signature generation
- [ ] Integration with vulnerability databases
- [ ] Custom port range specifications
- [ ] Configuration file support