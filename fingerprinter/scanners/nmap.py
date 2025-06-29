import asyncio
import xml.etree.ElementTree as ET
from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport, PortInfo

# Scanner metadata
SCANNER_INFO = {
    'name': 'nmap',
    'description': 'Comprehensive network service detection and fingerprinting using nmap',
    'target_types': ['ip', 'hostname'],
    'capabilities': [
        'Service version detection',
        'OS fingerprinting',
        'Raw fingerprint capture',
        'Banner grabbing',
        'Port scanning'
    ],
    'requirements': ['nmap command-line tool']
}


async def scan(ctx: ScanContext, report: ScanReport, log) -> None:
    """
    Perform comprehensive nmap service version scan (-sV) and collect fingerprints.
    Works with IP addresses and hostnames.
    """
    if not ctx.target.is_network_target:
        log.debug(f"Skipping nmap scan for {ctx.target_type} target")
        return

    log.info(f"Starting nmap service version scan on {ctx.display_name}")

    try:
        # Run nmap with service version detection
        xml_output, text_output = await _run_nmap(ctx, log)

        if xml_output:
            _parse_nmap_xml(xml_output, report, log)
            if text_output:
                _parse_raw_fingerprints(text_output, report, log)
            log.info(f"Nmap scan completed for {ctx.display_name}")
        else:
            log.warning(f"No nmap results for {ctx.display_name}")

    except Exception as e:
        log.error(f"Nmap scan failed: {e}")
        report.notes.append(f"Nmap error: {str(e)}")


async def _run_nmap(ctx: ScanContext, log) -> tuple[str | None, str | None]:
    """Execute comprehensive nmap -sV scan and return XML output and text output."""

    import tempfile
    import os

    # Create temporary file for XML output
    xml_fd, xml_file = tempfile.mkstemp(suffix='.xml', prefix='nmap_')

    try:
        os.close(xml_fd)  # Close the file descriptor, we just need the filename

        # Build nmap command that outputs XML to file and verbose to stdout/stderr
        cmd = [
            "nmap",
            "-sV",  # Service version detection
            "-sT",  # TCP connect scan
            "--version-intensity", "9",  # Maximum version detection intensity
            "-T4",  # Aggressive timing template
            f"--host-timeout={int(ctx.timeout * 150)}s",  # Much longer timeout for service detection
            f"--max-rtt-timeout={int(ctx.timeout * 5000)}ms",  # Higher RTT timeout
            "-v", "-v",  # Double verbose to ensure fingerprints are shown
            "-oX", xml_file,  # XML output to file
            ctx.target_value
        ]

        # Add port specification - scan top 1000 ports by default
        # This matches the default nmap behavior shown in the CLI output
        if ctx.interactive:
            # In interactive mode, scan common ports only
            cmd.extend(["-p", "22,23,53,80,443,8080,8443,49152"])
        # Otherwise use nmap's default top 1000 ports

        log.debug(f"Running nmap command: {' '.join(cmd)}")

        # Run nmap command
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=ctx.timeout * 120  # Allow much more time for service detection with fingerprints
        )

        xml_data = None
        text_data = ""

        # Read XML from file
        try:
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                xml_data = f.read()
                log.debug(f"Nmap XML output length: {len(xml_data)} bytes")
        except Exception as e:
            log.error(f"Failed to read XML file: {e}")

        # Combine stdout and stderr for verbose output containing fingerprints
        if stdout:
            stdout_text = stdout.decode('utf-8', errors='ignore')
            text_data += stdout_text
            log.debug(f"Nmap stdout output length: {len(stdout_text)} bytes")

        if stderr:
            stderr_text = stderr.decode('utf-8', errors='ignore')
            text_data += "\n" + stderr_text
            log.debug(f"Nmap stderr output length: {len(stderr_text)} bytes")

        # Check combined output for raw fingerprints
        if text_data:
            if "NEXT SERVICE FINGERPRINT" in text_data:
                log.info("Raw fingerprints detected in nmap output!")
                fingerprint_count = text_data.count("NEXT SERVICE FINGERPRINT")
                log.info(f"Found {fingerprint_count} raw fingerprints")
            elif "services unrecognized despite returning data" in text_data:
                log.info("Unrecognized services detected - fingerprints may be present")
            else:
                log.debug("No raw fingerprints found in nmap output")

        return xml_data, text_data if text_data and text_data.strip() else None

    except FileNotFoundError:
        log.error("nmap not found - please install nmap")
        return None, None
    except asyncio.TimeoutError:
        log.warning(f"nmap timeout for {ctx.target}")
        return None, None
    except Exception as e:
        log.error(f"nmap execution error: {e}")
        return None, None
    finally:
        # Clean up temporary XML file
        try:
            if os.path.exists(xml_file):
                os.unlink(xml_file)
        except Exception as e:
            log.debug(f"Failed to cleanup temp file {xml_file}: {e}")


def _parse_nmap_xml(xml_data: str, report: ScanReport, log) -> None:
    """Parse nmap XML and extract service fingerprints and OS info."""

    try:
        log.debug(f"Parsing XML data: {xml_data[:500]}...")
        root = ET.fromstring(xml_data)

        # Find the host element
        host = root.find('host')
        if not host:
            log.debug("No host element found in XML")
            return

        # Check host status
        status = host.find('status')
        if status is not None:
            state = status.get('state')
            log.debug(f"Host state: {state}")
            if state != 'up':
                log.info(f"Host {report.target} is {state}")
                return

        # Extract OS fingerprints
        _extract_os_info(host, report, log)

        # Extract port/service information
        _extract_port_info(host, report, log)

        # Extract additional host info
        _extract_host_info(host, report, log)

    except ET.ParseError as e:
        log.error(f"XML parse error: {e}")
        log.debug(f"Problematic XML: {xml_data[:1000]}")
    except Exception as e:
        log.error(f"Error parsing nmap results: {e}")


def _extract_os_info(host_elem, report: ScanReport, log) -> None:
    """Extract OS detection information from OS element and service entries."""

    # First try traditional OS detection
    os_elem = host_elem.find('os')
    if os_elem:
        # Extract OS matches
        for osmatch in os_elem.findall('osmatch'):
            name = osmatch.get('name')
            accuracy = osmatch.get('accuracy')
            if name and accuracy:
                report.notes.append(f"OS: {name} ({accuracy}% confidence)")
                log.debug(f"OS detected: {name} ({accuracy}%)")

        # Extract OS classes
        for osclass in os_elem.findall('osclass'):
            vendor = osclass.get('vendor')
            family = osclass.get('osfamily')
            gen = osclass.get('osgen')
            accuracy = osclass.get('accuracy')

            if vendor and family:
                os_info = f"{vendor} {family}"
                if gen:
                    os_info += f" {gen}"
                if accuracy:
                    os_info += f" ({accuracy}% confidence)"
                report.notes.append(f"OS Class: {os_info}")

    # Also extract OS info from service entries
    ports_elem = host_elem.find('ports')
    if ports_elem:
        os_info_found = set()  # Track unique OS info to avoid duplicates

        for port_elem in ports_elem.findall('port'):
            service_elem = port_elem.find('service')
            if service_elem:
                # Extract ostype attribute
                ostype = service_elem.get('ostype')
                if ostype and ostype not in os_info_found:
                    report.notes.append(f"OS detected from service: {ostype}")
                    os_info_found.add(ostype)
                    log.debug(f"OS from service: {ostype}")

                # Extract OS info from CPE
                for cpe_elem in service_elem.findall('cpe'):
                    if cpe_elem.text and cpe_elem.text.startswith('cpe:/o:'):
                        cpe_parts = cpe_elem.text.split(':')
                        if len(cpe_parts) >= 4:
                            vendor = cpe_parts[2].replace('_', ' ')
                            product = cpe_parts[3].replace('_', ' ')
                            version = cpe_parts[4].replace('_', ' ') if len(cpe_parts) > 4 else ''

                            os_string = f"{vendor} {product}"
                            if version:
                                os_string += f" {version}"

                            if os_string not in os_info_found:
                                report.notes.append(f"OS (CPE): {os_string}")
                                os_info_found.add(os_string)
                                log.debug(f"OS from CPE: {os_string}")


def _extract_port_info(host_elem, report: ScanReport, log) -> None:
    """Extract port and service information."""

    ports_elem = host_elem.find('ports')
    if not ports_elem:
        log.debug("No ports element found in XML")
        return

    ports = ports_elem.findall('port')
    log.debug(f"Found {len(ports)} port elements in XML")

    for port_elem in ports:
        port_info = _create_port_info(port_elem, log)
        if port_info:
            report.ports.append(port_info)
            log.debug(f"Added port: {port_info.port}/{port_info.proto} - {port_info.service}")
        else:
            port_num = port_elem.get('portid', 'unknown')
            protocol = port_elem.get('protocol', 'unknown')
            state_elem = port_elem.find('state')
            state = state_elem.get('state') if state_elem is not None else 'unknown'
            log.debug(f"Skipped port {port_num}/{protocol} (state: {state})")


def _create_port_info(port_elem, log) -> PortInfo | None:
    """Create PortInfo object from XML port element."""

    try:
        port_num = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol', 'tcp')
        log.debug(f"Processing port {port_num}/{protocol}")

        # Get port state
        state_elem = port_elem.find('state')
        if state_elem is None:
            log.debug(f"No state element for port {port_num}/{protocol}")
            return None

        state = state_elem.get('state')
        reason = state_elem.get('reason', '')
        log.debug(f"Port {port_num}/{protocol} state: {state} ({reason})")

        # Only include open ports in results (filtered ports don't provide useful service info)
        if state != 'open':
            log.debug(f"Excluding port {port_num}/{protocol} - state is {state}")
            return None

        # Get service information
        service_elem = port_elem.find('service')
        service_info = _parse_service_element(service_elem) if service_elem else {}

        # Build banner from available information
        banner = _build_banner(service_info, state, reason)

        # Create fingerprint signature
        fingerprint = _build_fingerprint(service_info)

        return PortInfo(
            port=port_num,
            proto=protocol,
            banner=banner,
            service=service_info.get('name'),
            product=service_info.get('product'),
            version=service_info.get('version'),
            extrainfo=service_info.get('extrainfo'),
            confidence=service_info.get('conf'),
            method=service_info.get('method'),
            fingerprint=fingerprint
        )

    except (ValueError, TypeError) as e:
        log.debug(f"Error creating port info: {e}")
        return None


def _parse_service_element(service_elem) -> dict:
    """Parse service element and extract all available information."""

    service_info = {}

    # Basic service attributes
    for attr in ['name', 'product', 'version', 'extrainfo', 'method', 'tunnel']:
        value = service_elem.get(attr)
        if value:
            service_info[attr] = value

    # Numeric attributes
    conf = service_elem.get('conf')
    if conf and conf.isdigit():
        service_info['conf'] = int(conf)

    # Handle CPE (Common Platform Enumeration) information
    cpes = []
    for cpe_elem in service_elem.findall('cpe'):
        if cpe_elem.text:
            cpes.append(cpe_elem.text)
    if cpes:
        service_info['cpe'] = cpes

    return service_info


def _build_banner(service_info: dict, state: str, reason: str) -> str:
    """Build a descriptive banner from service information."""

    banner_parts = []

    # Add service name with SSL tunnel indication
    service_name = service_info.get('name')
    tunnel = service_info.get('tunnel')

    if service_name:
        if tunnel == 'ssl':
            banner_parts.append(f"ssl/{service_name}")
        else:
            banner_parts.append(service_name)

    # Add product and version
    product = service_info.get('product')
    version = service_info.get('version')

    if product:
        if version:
            banner_parts.append(f"{product} {version}")
        else:
            banner_parts.append(product)
    elif version:
        banner_parts.append(version)

    # Add extra info in parentheses
    extrainfo = service_info.get('extrainfo')
    if extrainfo:
        banner_parts.append(f"({extrainfo})")

    # If no service info available, use state information
    if not banner_parts:
        banner_parts.append(f"open ({reason})")

    return " ".join(banner_parts) if banner_parts else None


def _build_fingerprint(service_info: dict) -> str | None:
    """Build a structured fingerprint from service information."""

    fp_parts = []

    # Add key service attributes to fingerprint
    for key in ['name', 'product', 'version', 'tunnel']:
        value = service_info.get(key)
        if value:
            fp_parts.append(f"{key}:{value}")

    # Add confidence if available
    conf = service_info.get('conf')
    if conf:
        fp_parts.append(f"conf:{conf}")

    return "|".join(fp_parts) if fp_parts else None


def _extract_host_info(host_elem, report: ScanReport, log) -> None:
    """Extract additional host information."""

    # Extract hostnames
    hostnames_elem = host_elem.find('hostnames')
    if hostnames_elem:
        for hostname_elem in hostnames_elem.findall('hostname'):
            name = hostname_elem.get('name')
            hostname_type = hostname_elem.get('type')
            if name:
                report.notes.append(f"Hostname: {name} ({hostname_type})")

    # Extract timing information
    times_elem = host_elem.find('times')
    if times_elem:
        srtt = times_elem.get('srtt')
        rttvar = times_elem.get('rttvar')
        to = times_elem.get('to')
        if srtt:
            report.notes.append(f"RTT: {srtt}ms")

    # Extract distance (TTL hops)
    distance_elem = host_elem.find('distance')
    if distance_elem:
        value = distance_elem.get('value')
        if value:
            report.notes.append(f"Network distance: {value} hops")


def _parse_raw_fingerprints(text_output: str, report: ScanReport, log) -> None:
    """Parse raw fingerprint data from nmap text output."""

    try:
        # Look for service fingerprint sections
        fingerprint_sections = []
        lines = text_output.split('\n')

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for fingerprint start marker
            if "NEXT SERVICE FINGERPRINT" in line and "SUBMIT INDIVIDUALLY" in line:
                # Found start of fingerprint section
                fingerprint_lines = []
                i += 1

                # Collect all lines until we hit another fingerprint or end
                while i < len(lines):
                    current_line = lines[i].strip()
                    if ("NEXT SERVICE FINGERPRINT" in current_line and
                        "SUBMIT INDIVIDUALLY" in current_line):
                        # Hit next fingerprint, back up
                        i -= 1
                        break
                    elif current_line.startswith("SF-Port"):
                        fingerprint_lines.append(current_line)
                    elif current_line and not current_line.startswith("="):
                        # Continuation line
                        fingerprint_lines.append(current_line)
                    elif not current_line:
                        # Empty line might end the fingerprint
                        break
                    i += 1

                if fingerprint_lines:
                    fingerprint_sections.append('\n'.join(fingerprint_lines))

            i += 1

        # Process each fingerprint section
        for fingerprint_text in fingerprint_sections:
            port_num = _extract_port_from_fingerprint(fingerprint_text)
            if port_num:
                # Find matching port in report and add raw fingerprint
                for port_info in report.ports:
                    if port_info.port == port_num and port_info.proto == "tcp":
                        port_info.raw_fingerprint = fingerprint_text
                        log.debug(f"Added raw fingerprint for port {port_num}")
                        break
                else:
                    # Port not found in existing results, create new entry
                    log.debug(f"Creating new port entry for fingerprint on port {port_num}")
                    from fingerprinter.core.result import PortInfo
                    port_info = PortInfo(
                        port=port_num,
                        proto="tcp",
                        raw_fingerprint=fingerprint_text,
                        service="unknown"
                    )
                    report.ports.append(port_info)

        if fingerprint_sections:
            log.info(f"Extracted {len(fingerprint_sections)} raw fingerprints")

    except Exception as e:
        log.error(f"Error parsing raw fingerprints: {e}")


def _extract_port_from_fingerprint(fingerprint_text: str) -> int | None:
    """Extract port number from raw fingerprint text."""

    try:
        # Look for SF-PortXXX-TCP pattern
        import re
        match = re.search(r'SF-Port(\d+)-TCP:', fingerprint_text)
        if match:
            return int(match.group(1))
    except Exception:
        pass

    return None
