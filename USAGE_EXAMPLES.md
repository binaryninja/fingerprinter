# Fingerprinter Usage Examples

This document provides comprehensive examples of using the refactored fingerprinter tool, which now supports multiple target types beyond just IP addresses.

## Quick Start

```bash
# Show available examples
python -m fingerprinter examples

# Basic network scan (traditional usage)
python -m fingerprinter --legal-ok 192.168.1.1

# RF spectrum survey
python -m fingerprinter --legal-ok rf-survey --location 'Home Lab'

# Location-based scanning
python -m fingerprinter --legal-ok 37.7749,-122.4194 --target-type coordinates
```

## Target Types

The fingerprinter now supports multiple target types with automatic detection:

### Network Targets

#### IP Addresses
```bash
# IPv4 scanning
python -m fingerprinter --legal-ok 192.168.1.1

# IPv6 scanning
python -m fingerprinter --legal-ok 2001:db8::1

# Add context and location
python -m fingerprinter --legal-ok 192.168.1.1 \
  --location 'Home Office' \
  --note 'Router security audit'
```

#### Hostnames
```bash
# Domain scanning
python -m fingerprinter --legal-ok example.com

# Local hostname
python -m fingerprinter --legal-ok router.local

# With specific scanners
python -m fingerprinter --legal-ok example.com -m nmap -m http
```

#### URLs
```bash
# Web application scanning
python -m fingerprinter --legal-ok https://example.com

# Specific port/path
python -m fingerprinter --legal-ok http://192.168.1.1:8080
```

### RF Spectrum Targets

#### General RF Survey
```bash
# Basic RF survey with location context
python -m fingerprinter --legal-ok rf-survey-office \
  --location 'Office Floor 2'

# Comprehensive RF analysis
python -m fingerprinter --legal-ok weekly-rf-check \
  --location 'Data Center' \
  --note 'Weekly interference check' \
  -m hackrf

# Quick RF scan (interactive mode)
python -m fingerprinter --legal-ok rf-quick \
  --location 'Meeting Room A' \
  --interactive
```

#### Geographic Coordinates
```bash
# Coordinates-based RF survey
python -m fingerprinter --legal-ok 37.7749,-122.4194 \
  --target-type coordinates \
  --location 'San Francisco Downtown'

# Combined with notes
python -m fingerprinter --legal-ok 40.7128,-74.0060 \
  --target-type coordinates \
  --location 'NYC Manhattan' \
  --note 'Urban RF environment study'
```

### Device-Specific Targets

#### MAC Addresses
```bash
# Device investigation by MAC
python -m fingerprinter --legal-ok AA:BB:CC:DD:EE:FF \
  --target-type mac \
  --note 'Suspected IoT device'

# Bluetooth device analysis
python -m fingerprinter --legal-ok 12:34:56:78:9A:BC \
  --target-type bluetooth
```

#### File-Based Targets
```bash
# Configuration file analysis
python -m fingerprinter --legal-ok /etc/network/interfaces \
  --target-type file

# Log file investigation
python -m fingerprinter --legal-ok /var/log/syslog \
  --target-type file
```

## Scanner Selection

### Automatic Scanner Selection
The tool automatically selects compatible scanners based on target type:

```bash
# IP target - runs nmap, http, port, arp, hackrf
python -m fingerprinter --legal-ok 192.168.1.1

# RF survey - runs hackrf only
python -m fingerprinter --legal-ok rf-survey --location 'Lab'

# Coordinates - runs hackrf only
python -m fingerprinter --legal-ok 37.7749,-122.4194 --target-type coordinates
```

### Manual Scanner Selection
```bash
# Specific scanners only
python -m fingerprinter --legal-ok 192.168.1.1 -m nmap -m http

# RF scanning only
python -m fingerprinter --legal-ok 192.168.1.1 -m hackrf

# Exclude specific scanners
python -m fingerprinter --legal-ok 192.168.1.1 --exclude-module arp
```

## Output Options

### JSON Output
```bash
# Custom JSON filename
python -m fingerprinter --legal-ok 192.168.1.1 \
  --json-out router-audit-2025.json

# Auto-generated filename (default)
python -m fingerprinter --legal-ok rf-survey
# Creates: scan_rf-survey_20250629_120000.json
```

### Markdown Reports
```bash
# Generate both JSON and markdown (default)
python -m fingerprinter --legal-ok 192.168.1.1

# JSON only (skip markdown)
python -m fingerprinter --legal-ok 192.168.1.1 --no-markdown
```

## Advanced Usage Scenarios

### Comprehensive Network + RF Analysis
```bash
# Complete environment analysis
python -m fingerprinter --legal-ok 192.168.1.1 \
  --location 'Home Network' \
  --note 'Monthly security audit' \
  --note 'Check for new IoT devices'
# Runs all compatible scanners: nmap, http, port, arp, hackrf
```

### IoT Device Investigation
```bash
# Network analysis of suspected IoT device
python -m fingerprinter --legal-ok 192.168.1.100 \
  --location 'Smart Home Lab' \
  --note 'New device appeared on network'

# RF analysis to detect wireless activity
python -m fingerprinter --legal-ok iot-device-check \
  --location 'Smart Home Lab' \
  --note 'Check for 433MHz/915MHz activity' \
  -m hackrf
```

### Security Assessment Workflow
```bash
# Step 1: Network reconnaissance
python -m fingerprinter --legal-ok 192.168.1.0/24 \
  --location 'Target Network' \
  --note 'Initial recon phase'

# Step 2: Detailed service analysis
python -m fingerprinter --legal-ok 192.168.1.50 \
  --location 'Target Network' \
  --note 'Detailed service fingerprinting' \
  -m nmap -m http

# Step 3: RF environment assessment
python -m fingerprinter --legal-ok security-rf-check \
  --location 'Target Network' \
  --note 'RF surveillance detection' \
  -m hackrf
```

### Research and Development
```bash
# RF propagation study
python -m fingerprinter --legal-ok 37.7749,-122.4194 \
  --target-type coordinates \
  --location 'Golden Gate Park' \
  --note 'Urban RF propagation study' \
  --note 'Weather: clear, 72F'

# Technology fingerprinting
python -m fingerprinter --legal-ok research-target \
  --location 'R&D Lab' \
  --note 'New protocol analysis' \
  --note 'Baseline measurement'
```

## Interactive Mode

```bash
# Interactive analysis (coming soon)
python -m fingerprinter --legal-ok 192.168.1.1 --interactive

# Quick interactive RF scan
python -m fingerprinter --legal-ok rf-interactive \
  --location 'Conference Room' \
  --interactive -m hackrf
```

## Configuration Tips

### Timeout Settings
```bash
# Increase timeout for slow networks
python -m fingerprinter --legal-ok 192.168.1.1 --timeout 10.0

# Quick scan mode
python -m fingerprinter --legal-ok 192.168.1.1 --quick
```

### Verbosity Levels
```bash
# Normal output
python -m fingerprinter --legal-ok 192.168.1.1

# Verbose output
python -m fingerprinter --legal-ok 192.168.1.1 -v

# Debug output
python -m fingerprinter --legal-ok 192.168.1.1 -vv
```

## Understanding Output

### Scan IDs
Each scan gets a unique ID based on target and timestamp:
- `192.168.1.1_20250629_120000` - IP scan
- `rf-survey_20250629_120000` - RF survey
- `example.com_20250629_120000` - Hostname scan

### Target Types in Reports
- `ip`: IPv4/IPv6 addresses
- `hostname`: Domain names and hostnames
- `coordinates`: Geographic coordinates (lat,lon)
- `identifier`: General identifiers for RF surveys
- `mac`: MAC addresses
- `bluetooth`: Bluetooth addresses
- `file`: File paths
- `url`: Web URLs

### Scanner Compatibility
| Scanner | IP | Hostname | Coordinates | Identifier | MAC | File |
|---------|----|---------|-----------|-----------|----|------|
| nmap    | ✅  | ✅       | ❌         | ❌         | ❌  | ❌   |
| http    | ✅  | ✅       | ❌         | ❌         | ❌  | ❌   |
| port    | ✅  | ✅       | ❌         | ❌         | ❌  | ❌   |
| arp     | ✅  | ❌       | ❌         | ❌         | ❌  | ❌   |
| hackrf  | ✅  | ✅       | ✅         | ✅         | ✅  | ✅   |

## Migration from Old Version

### Legacy IP-Only Usage (Still Supported)
```bash
# Old way (still works)
python -m fingerprinter --legal-ok 192.168.1.1

# New way (same result, more explicit)
python -m fingerprinter --legal-ok 192.168.1.1 --target-type ip
```

### New Capabilities
```bash
# What you can now do that wasn't possible before:
python -m fingerprinter --legal-ok rf-survey --location 'Lab'
python -m fingerprinter --legal-ok 37.7749,-122.4194 --target-type coordinates
python -m fingerprinter --legal-ok investigation --note 'Context info'
```

## Troubleshooting

### Common Issues

#### Target Type Detection
```bash
# If auto-detection fails, specify manually
python -m fingerprinter --legal-ok ambiguous-target --target-type identifier

# Force IP mode for backward compatibility
python -m fingerprinter --legal-ok 192.168.1.1 --legacy-ip-mode
```

#### Scanner Compatibility
```bash
# Check what scanners will run
python -m fingerprinter --legal-ok rf-survey -v
# Shows: "Auto-selected compatible scanners: hackrf"

# Force incompatible scanner (will be skipped with warning)
python -m fingerprinter --legal-ok rf-survey -m nmap
# Shows: "Skipping incompatible scanners for identifier target: nmap"
```

#### HackRF Setup
```bash
# Check HackRF availability
hackrf_info

# Fix permissions (Ubuntu/Debian)
sudo usermod -a -G plugdev $USER
# Then logout and login again

# Test RF scanning
python -m fingerprinter --legal-ok rf-test -m hackrf --location 'Test'
```

## Best Practices

### Security Considerations
1. Always use `--legal-ok` only on networks you own or have permission to scan
2. Add location and context notes for audit trails
3. Use specific scanner selection for targeted assessments

### Documentation
1. Use `--location` for physical context
2. Add `--note` for investigation context
3. Use descriptive target identifiers for RF surveys

### Performance
1. Use `--quick` for faster scans with reduced coverage
2. Specify scanners with `-m` to avoid unnecessary scanning
3. Adjust `--timeout` based on network conditions

## Getting Help

```bash
# Show help
python -m fingerprinter --help

# Show examples
python -m fingerprinter examples

# Version and scanner info
python -m fingerprinter --version  # (coming soon)
```

## Example Workflows

### Home Network Security Audit
```bash
# 1. Discover active devices
python -m fingerprinter --legal-ok 192.168.1.1 \
  --location 'Home Network' \
  --note 'Router audit'

# 2. Check for RF interference
python -m fingerprinter --legal-ok home-rf-survey \
  --location 'Home Network' \
  --note 'WiFi interference check' \
  -m hackrf

# 3. Investigate suspicious device
python -m fingerprinter --legal-ok 192.168.1.100 \
  --location 'Home Network' \
  --note 'Unknown device investigation'
```

### IoT Device Research
```bash
# 1. Network fingerprint
python -m fingerprinter --legal-ok 192.168.1.200 \
  --location 'IoT Lab' \
  --note 'New smart device analysis'

# 2. RF spectrum analysis
python -m fingerprinter --legal-ok iot-rf-analysis \
  --location 'IoT Lab' \
  --note 'Check 433/915MHz activity' \
  -m hackrf

# 3. Device correlation
python -m fingerprinter --legal-ok AA:BB:CC:DD:EE:FF \
  --target-type mac \
  --location 'IoT Lab' \
  --note 'MAC address correlation'
```

This refactored system provides much more flexibility while maintaining backward compatibility with existing IP-based workflows.