# Fingerprinter

A modular async IP fingerprinting tool with comprehensive service detection and raw fingerprint retention.

## Features

- **Multi-Scanner Architecture**: Modular design with ARP, HTTP, nmap, and port scanners
- **Raw Fingerprint Retention**: Captures and stores nmap raw fingerprints for unrecognized services
- **Comprehensive Service Detection**: Deep service identification with version detection
- **Multiple Output Formats**: JSON data output and markdown reports
- **Async Performance**: Non-blocking concurrent scanning
- **Port Deduplication**: Intelligent merging of results from multiple scanners

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
- Dependencies: rich, psutil, aiohttp, requests, cryptography

## Usage

### Basic Scanning

```bash
# Basic scan with legal acknowledgment
python -m fingerprinter --legal-ok <target_ip>

# Verbose output
python -m fingerprinter --legal-ok <target_ip> -vv

# Interactive mode
python -m fingerprinter --legal-ok <target_ip> --interactive

# Specific scanners only
python -m fingerprinter --legal-ok <target_ip> -m nmap -m http

# Custom JSON output file
python -m fingerprinter --legal-ok <target_ip> --json-out results.json
```

### Command Line Options

- `target`: IPv4/IPv6 address to scan
- `--legal-ok`: Required acknowledgment of legal authorization
- `-m, --module`: Specific scanner modules to run (can be used multiple times)
- `--json-out`: Custom path for JSON output file
- `--interactive`: Enable interactive menu (coming soon)
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

## Output Formats

### JSON Output
Complete structured data including:
- Port information with banners and service details
- **Raw fingerprints** for unrecognized services
- HTTP service details with technology signatures
- Network and OS information
- Scan metadata and timing

### Markdown Reports
Human-readable reports featuring:
- Open ports with service descriptions
- Raw fingerprint display for unknown services
- Web services with status codes and signatures
- Additional notes and findings

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

### Comprehensive Network Device Scan

```bash
# Scan a router with full verbose output
python -m fingerprinter --legal-ok 192.168.1.1 -vv

# Output includes:
# - Open ports with service detection
# - Raw fingerprints for unidentified services
# - HTTP services and web interfaces
# - Device signatures and OS detection
```

### JSON Output Structure

```json
{
  "target": "192.168.1.1",
  "started": "2025-06-28T20:46:27.937929",
  "finished": "2025-06-28T20:52:21.651566",
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
  "notes": [
    "OS detected: Linux",
    "Device: Router Interface"
  ]
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
│   └── arp.py           # ARP scanning
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

- [ ] Add support for hackrf frequency scan
- [ ] Interactive mode implementation
- [ ] Raw fingerprint analysis and signature generation
- [ ] Integration with vulnerability databases
- [ ] Custom port range specifications
- [ ] Configuration file support