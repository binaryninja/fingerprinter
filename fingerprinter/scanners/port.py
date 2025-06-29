import asyncio
import socket
from typing import List, Optional, Tuple
from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport, PortInfo


async def scan(ctx: ScanContext, report: ScanReport, log) -> None:
    """
    Perform basic port scanning with service detection.
    """
    log.info(f"Starting port scan on {ctx.target}")

    # Common ports for Google/Nest WiFi devices and general services
    common_ports = [22, 23, 53, 80, 443, 8080, 8081, 8443, 9000, 50000, 50001]

    # Additional ports for comprehensive scanning
    extended_ports = [21, 25, 110, 143, 993, 995, 3389, 5900, 8000, 8888, 9090]

    # Use common ports by default, extend if not interactive
    ports_to_scan = common_ports
    if not ctx.interactive:
        ports_to_scan.extend(extended_ports)

    try:
        # Scan TCP ports
        tcp_results = await _scan_tcp_ports(ctx, ports_to_scan, log)

        # Scan UDP ports (limited set)
        udp_ports = [53, 67, 68, 123, 161, 500, 4500]
        udp_results = await _scan_udp_ports(ctx, udp_ports, log)

        # Combine results
        all_results = tcp_results + udp_results

        # Add to report
        report.ports.extend(all_results)

        if all_results:
            log.info(f"Found {len(all_results)} open ports on {ctx.target}")
        else:
            log.info(f"No open ports found on {ctx.target}")

    except Exception as e:
        log.error(f"Port scan failed for {ctx.target}: {str(e)}")
        report.notes.append(f"Port scan error: {str(e)}")


async def _scan_tcp_ports(ctx: ScanContext, ports: List[int], log) -> List[PortInfo]:
    """
    Scan TCP ports and detect services.
    """
    tasks = []
    for port in ports:
        task = _scan_tcp_port(ctx, port, log)
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for result in results:
        if isinstance(result, PortInfo):
            open_ports.append(result)
        elif isinstance(result, Exception):
            log.debug(f"Port scan exception: {result}")

    return open_ports


async def _scan_tcp_port(ctx: ScanContext, port: int, log) -> Optional[PortInfo]:
    """
    Scan a single TCP port and attempt service detection.
    """
    try:
        # Connect to port
        future = asyncio.open_connection(str(ctx.ip), port)
        reader, writer = await asyncio.wait_for(future, timeout=ctx.timeout)

        log.debug(f"Port {port}/tcp is open on {ctx.target}")

        # Attempt banner grabbing
        banner = await _grab_tcp_banner(reader, writer, port, ctx.timeout)

        # Close connection
        writer.close()
        await writer.wait_closed()

        # Detect service based on port and banner
        service_info = _detect_tcp_service(port, banner)

        return PortInfo(
            port=port,
            proto="tcp",
            banner=banner,
            service=service_info.get('service'),
            product=service_info.get('product'),
            version=service_info.get('version'),
            fingerprint=service_info.get('fingerprint')
        )

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # Port is closed or filtered
        return None
    except Exception as e:
        log.debug(f"Error scanning port {port}/tcp: {e}")
        return None


async def _grab_tcp_banner(reader, writer, port: int, timeout: float) -> Optional[str]:
    """
    Attempt to grab banner from TCP service.
    """
    try:
        # Send appropriate probe based on port
        probe = _get_tcp_probe(port)
        if probe:
            writer.write(probe)
            await writer.drain()

        # Read response
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)

        if data:
            banner = data.decode('utf-8', errors='ignore').strip()
            # Clean up banner (remove control characters)
            banner = ''.join(char for char in banner if ord(char) >= 32 or char in '\n\r\t')
            return banner[:200]  # Limit banner length

    except (asyncio.TimeoutError, UnicodeDecodeError, ConnectionResetError):
        pass
    except Exception:
        pass

    return None


def _get_tcp_probe(port: int) -> Optional[bytes]:
    """
    Get appropriate probe for specific TCP ports.
    """
    probes = {
        21: b"HELP\r\n",                    # FTP
        22: b"SSH-2.0-Test\r\n",           # SSH
        23: b"\r\n",                       # Telnet
        25: b"EHLO test\r\n",              # SMTP
        53: b"",                           # DNS (no probe needed)
        80: b"GET / HTTP/1.0\r\n\r\n",     # HTTP
        110: b"USER test\r\n",             # POP3
        143: b"A001 CAPABILITY\r\n",       # IMAP
        443: b"",                          # HTTPS (TLS handshake too complex)
        993: b"",                          # IMAPS
        995: b"",                          # POP3S
    }

    return probes.get(port, b"")


def _detect_tcp_service(port: int, banner: Optional[str]) -> dict:
    """
    Detect service based on port number and banner.
    """
    # Common port to service mappings
    port_services = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        993: "imaps",
        995: "pop3s",
        3389: "rdp",
        5900: "vnc",
        8000: "http-alt",
        8080: "http-proxy",
        8081: "http-alt",
        8443: "https-alt",
        8888: "http-alt",
        9000: "http-alt",
        9090: "http-alt",
        50000: "unknown",
        50001: "unknown"
    }

    service_info = {
        'service': port_services.get(port),
        'product': None,
        'version': None,
        'fingerprint': None
    }

    if banner:
        # Analyze banner for service details
        banner_lower = banner.lower()

        # SSH detection
        if 'ssh' in banner_lower:
            service_info['service'] = 'ssh'
            if 'openssh' in banner_lower:
                service_info['product'] = 'OpenSSH'
            # Extract version
            import re
            version_match = re.search(r'ssh-[\d.]+[_-]([^\s\r\n]+)', banner, re.IGNORECASE)
            if version_match:
                service_info['version'] = version_match.group(1)

        # HTTP detection
        elif 'http' in banner_lower or 'server:' in banner_lower:
            service_info['service'] = 'http'
            # Extract server info
            server_match = re.search(r'server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if server_match:
                server_info = server_match.group(1).strip()
                service_info['product'] = server_info

        # FTP detection
        elif 'ftp' in banner_lower:
            service_info['service'] = 'ftp'
            if 'vsftpd' in banner_lower:
                service_info['product'] = 'vsftpd'
            elif 'proftpd' in banner_lower:
                service_info['product'] = 'ProFTPD'

        # Telnet detection
        elif 'telnet' in banner_lower or port == 23:
            service_info['service'] = 'telnet'

        # Create fingerprint
        if service_info['service']:
            fp_parts = [f"service:{service_info['service']}"]
            if service_info['product']:
                fp_parts.append(f"product:{service_info['product']}")
            if service_info['version']:
                fp_parts.append(f"version:{service_info['version']}")
            service_info['fingerprint'] = "|".join(fp_parts)

    return service_info


async def _scan_udp_ports(ctx: ScanContext, ports: List[int], log) -> List[PortInfo]:
    """
    Scan UDP ports (limited functionality).
    """
    tasks = []
    for port in ports:
        task = _scan_udp_port(ctx, port, log)
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for result in results:
        if isinstance(result, PortInfo):
            open_ports.append(result)

    return open_ports


async def _scan_udp_port(ctx: ScanContext, port: int, log) -> Optional[PortInfo]:
    """
    Scan a single UDP port.
    """
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(ctx.timeout)

        # Send probe
        probe = _get_udp_probe(port)
        sock.sendto(probe, (str(ctx.ip), port))

        # Try to receive response
        try:
            data, addr = sock.recvfrom(1024)
            banner = data.decode('utf-8', errors='ignore').strip()[:200]

            service_info = _detect_udp_service(port, banner)

            return PortInfo(
                port=port,
                proto="udp",
                banner=banner,
                service=service_info.get('service'),
                fingerprint=service_info.get('fingerprint')
            )
        except socket.timeout:
            # No response - might still be open
            service_info = _detect_udp_service(port, None)
            return PortInfo(
                port=port,
                proto="udp",
                service=service_info.get('service'),
                fingerprint=service_info.get('fingerprint')
            )

    except Exception as e:
        log.debug(f"Error scanning UDP port {port}: {e}")
        return None
    finally:
        sock.close()


def _get_udp_probe(port: int) -> bytes:
    """
    Get appropriate probe for UDP ports.
    """
    probes = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",  # DNS query
        67: b"",   # DHCP
        68: b"",   # DHCP
        123: b"\x1b" + b"\x00" * 47,  # NTP
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
        500: b"",  # IKE
        4500: b"",  # IPSec NAT-T
    }

    return probes.get(port, b"")


def _detect_udp_service(port: int, banner: str | None) -> dict:
    """
    Detect UDP service based on port and response.
    """
    port_services = {
        53: "domain",
        67: "dhcps",
        68: "dhcpc",
        123: "ntp",
        161: "snmp",
        500: "isakmp",
        4500: "ipsec-nat-t"
    }

    service_info = {
        'service': port_services.get(port),
        'fingerprint': None
    }

    if banner and service_info['service']:
        service_info['fingerprint'] = f"service:{service_info['service']}"

    return service_info
