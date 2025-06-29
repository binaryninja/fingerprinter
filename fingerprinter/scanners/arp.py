import asyncio
import subprocess
from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport


async def scan(ctx: ScanContext, report: ScanReport, log) -> None:
    """
    Perform ARP scanning to detect local network devices.
    """
    # Only perform ARP scan for local network addresses
    if not _is_local_network(str(ctx.ip)):
        log.debug(f"Skipping ARP scan for non-local address {ctx.target}")
        return

    log.info(f"Starting ARP scan for {ctx.target}")

    try:
        # Try to get ARP entry
        arp_info = await _get_arp_info(ctx, log)

        if arp_info:
            report.notes.append(f"ARP: {arp_info}")
            log.info(f"ARP info found for {ctx.target}: {arp_info}")
        else:
            log.debug(f"No ARP info found for {ctx.target}")

    except Exception as e:
        log.error(f"ARP scan failed: {e}")
        report.notes.append(f"ARP scan error: {str(e)}")


def _is_local_network(ip_str: str) -> bool:
    """
    Check if IP address is in a local network range.
    """
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_str)

        # Check for private networks
        if ip.is_private:
            return True

        # Check for link-local
        if ip.is_link_local:
            return True

        # Check for loopback
        if ip.is_loopback:
            return True

    except ValueError:
        pass

    return False


async def _get_arp_info(ctx: ScanContext, log) -> str | None:
    """
    Get ARP information for the target IP.
    """
    try:
        # Try to get ARP table entry
        proc = await asyncio.create_subprocess_exec(
            "arp", "-n", str(ctx.ip),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=ctx.timeout
        )

        if proc.returncode == 0 and stdout:
            output = stdout.decode('utf-8', errors='ignore').strip()

            # Parse ARP output
            lines = output.split('\n')
            for line in lines:
                if str(ctx.ip) in line and 'incomplete' not in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        # Format: IP HWtype HWaddress Flags Mask Iface
                        mac = parts[2] if parts[2] != "(incomplete)" else None
                        if mac and mac != "no" and ":" in mac:
                            return f"MAC {mac}"

        # If arp command failed or no entry, try ip neighbor
        proc2 = await asyncio.create_subprocess_exec(
            "ip", "neighbor", "show", str(ctx.ip),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout2, stderr2 = await asyncio.wait_for(
            proc2.communicate(),
            timeout=ctx.timeout
        )

        if proc2.returncode == 0 and stdout2:
            output2 = stdout2.decode('utf-8', errors='ignore').strip()

            # Parse ip neighbor output
            if output2 and str(ctx.ip) in output2:
                parts = output2.split()
                for i, part in enumerate(parts):
                    if ":" in part and len(part) == 17:  # MAC address format
                        return f"MAC {part}"

    except (FileNotFoundError, asyncio.TimeoutError):
        # Command not available or timeout
        pass
    except Exception as e:
        log.debug(f"ARP lookup error: {e}")

    return None
