import asyncio
import aiohttp
import re
from typing import List, Dict, Any
from fingerprinter.core.context import ScanContext
from fingerprinter.core.result import ScanReport, HttpInfo


async def scan(ctx: ScanContext, report: ScanReport, log) -> None:
    """
    Perform HTTP scanning and fingerprinting.
    """
    log.info(f"Starting HTTP scan on {ctx.target}")

    # Common HTTP ports to check
    http_ports = [80, 8080, 8081, 8000, 8888, 9000, 9090]
    https_ports = [443, 8443]

    try:
        # Scan HTTP ports
        http_tasks = []
        for port in http_ports:
            url = f"http://{ctx.ip}:{port}"
            http_tasks.append(_scan_http_url(url, ctx, log))

        # Scan HTTPS ports
        for port in https_ports:
            url = f"https://{ctx.ip}:{port}"
            http_tasks.append(_scan_http_url(url, ctx, log))

        # Execute all HTTP scans concurrently
        results = await asyncio.gather(*http_tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, HttpInfo):
                report.http.append(result)
                log.info(f"HTTP service found: {result.url} [{result.status}] {result.title}")
            elif isinstance(result, Exception):
                log.debug(f"HTTP scan exception: {result}")

        if report.http:
            log.info(f"Found {len(report.http)} HTTP services on {ctx.target}")
        else:
            log.debug(f"No HTTP services found on {ctx.target}")

    except Exception as e:
        log.error(f"HTTP scan failed for {ctx.target}: {str(e)}")
        report.notes.append(f"HTTP scan error: {str(e)}")


async def _scan_http_url(url: str, ctx: ScanContext, log) -> HttpInfo | None:
    """
    Scan a single HTTP URL and extract information.
    """
    try:
        timeout = aiohttp.ClientTimeout(total=ctx.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                allow_redirects=False,
                ssl=False  # Don't verify SSL certificates
            ) as response:
                log.debug(f"HTTP response from {url}: {response.status}")

                # Read response content (limited)
                content = ""
                try:
                    content = await response.text(encoding='utf-8', errors='ignore')
                    content = content[:10000]  # Limit content size
                except Exception:
                    # If we can't read as text, try as bytes
                    try:
                        raw_content = await response.read()
                        content = raw_content[:10000].decode('utf-8', errors='ignore')
                    except Exception:
                        content = ""

                # Extract title
                title = _extract_title(content)

                # Extract signatures/fingerprints
                signatures = _extract_signatures(response, content)

                return HttpInfo(
                    url=url,
                    status=response.status,
                    title=title,
                    signatures=signatures
                )

    except asyncio.TimeoutError:
        log.debug(f"HTTP timeout for {url}")
    except aiohttp.ClientConnectorError:
        log.debug(f"HTTP connection failed for {url}")
    except Exception as e:
        log.debug(f"HTTP error for {url}: {e}")

    return None


def _extract_title(content: str) -> str | None:
    """
    Extract page title from HTML content.
    """
    if not content:
        return None

    try:
        # Look for title tag
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # Clean up title
            title = re.sub(r'\s+', ' ', title)  # Normalize whitespace
            title = title[:200]  # Limit length
            return title if title else None

    except Exception:
        pass

    return None


def _extract_signatures(response, content: str) -> List[str]:
    """
    Extract technology signatures from HTTP response and content.
    """
    signatures = []

    try:
        # Check HTTP headers for signatures
        headers = response.headers

        # Server header
        server = headers.get('server', '').lower()
        if server:
            signatures.append(f"Server: {server}")

        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if powered_by:
            signatures.append(f"X-Powered-By: {powered_by}")

        # Other interesting headers
        interesting_headers = [
            'x-aspnet-version', 'x-aspnetmvc-version', 'x-framework',
            'x-generator', 'x-drupal-cache', 'x-varnish'
        ]

        for header in interesting_headers:
            value = headers.get(header, '')
            if value:
                signatures.append(f"{header}: {value}")

        # Check content for signatures
        if content:
            content_lower = content.lower()

            # Common CMS/Framework signatures
            content_signatures = [
                ('wordpress', 'WordPress'),
                ('wp-content', 'WordPress'),
                ('wp-includes', 'WordPress'),
                ('drupal', 'Drupal'),
                ('joomla', 'Joomla'),
                ('powered by django', 'Django'),
                ('angular', 'AngularJS'),
                ('react', 'React'),
                ('vue.js', 'Vue.js'),
                ('bootstrap', 'Bootstrap'),
                ('jquery', 'jQuery'),
                ('nginx', 'nginx'),
                ('apache', 'Apache'),
                ('lighttpd', 'lighttpd'),
                ('microsoft-iis', 'IIS'),
                ('tomcat', 'Apache Tomcat'),
                ('jetty', 'Jetty'),
                ('express', 'Express.js'),
                ('flask', 'Flask'),
                ('rails', 'Ruby on Rails'),
                ('laravel', 'Laravel'),
                ('symfony', 'Symfony'),
            ]

            for pattern, name in content_signatures:
                if pattern in content_lower:
                    signature = f"Content: {name}"
                    if signature not in signatures:
                        signatures.append(signature)

            # Look for generator meta tag
            generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if generator_match:
                generator = generator_match.group(1).strip()
                if generator:
                    signatures.append(f"Generator: {generator}")

            # Look for specific technology patterns
            tech_patterns = [
                (r'wp-json/wp/v2', 'WordPress REST API'),
                (r'/wp-admin/', 'WordPress Admin'),
                (r'/administrator/', 'Joomla Admin'),
                (r'/typo3/', 'TYPO3'),
                (r'Powered by.*?OpenCart', 'OpenCart'),
                (r'Magento', 'Magento'),
                (r'PrestaShop', 'PrestaShop'),
                (r'phpMyAdmin', 'phpMyAdmin'),
                (r'cPanel', 'cPanel'),
                (r'Plesk', 'Plesk'),
                (r'DirectAdmin', 'DirectAdmin'),
                (r'ISPConfig', 'ISPConfig'),
            ]

            for pattern, name in tech_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    signature = f"Technology: {name}"
                    if signature not in signatures:
                        signatures.append(signature)

        # Check for common router/device signatures
        if response.status == 200:
            device_signatures = _check_device_signatures(response, content)
            signatures.extend(device_signatures)

    except Exception as e:
        # Don't let signature extraction errors break the scan
        pass

    return signatures


def _check_device_signatures(response, content: str) -> List[str]:
    """
    Check for router and device-specific signatures.
    """
    signatures = []

    try:
        content_lower = content.lower() if content else ""
        headers = response.headers

        # Google/Nest WiFi signatures
        google_patterns = [
            ('google wifi', 'Google WiFi'),
            ('nest wifi', 'Nest WiFi'),
            ('onhub', 'OnHub'),
            ('google nest', 'Google Nest'),
            ('made by google', 'Google Device'),
        ]

        for pattern, name in google_patterns:
            if pattern in content_lower:
                signatures.append(f"Device: {name}")

        # Router signatures
        router_patterns = [
            ('linksys', 'Linksys Router'),
            ('netgear', 'Netgear Router'),
            ('d-link', 'D-Link Router'),
            ('tp-link', 'TP-Link Router'),
            ('asus', 'ASUS Router'),
            ('belkin', 'Belkin Router'),
            ('buffalo', 'Buffalo Router'),
            ('zyxel', 'ZyXEL Router'),
            ('ubiquiti', 'Ubiquiti Device'),
            ('mikrotik', 'MikroTik Router'),
            ('openwrt', 'OpenWrt'),
            ('dd-wrt', 'DD-WRT'),
            ('tomato', 'Tomato Firmware'),
            ('pfsense', 'pfSense'),
            ('router', 'Generic Router'),
            ('access point', 'Access Point'),
            ('wireless', 'Wireless Device'),
        ]

        for pattern, name in router_patterns:
            if pattern in content_lower:
                signatures.append(f"Device: {name}")

        # Check for device-specific headers
        device_headers = [
            ('www-authenticate', 'Authentication Required'),
            ('realm', 'Device Realm'),
        ]

        for header, desc in device_headers:
            value = headers.get(header, '')
            if value and any(device in value.lower() for device in ['router', 'access point', 'device']):
                signatures.append(f"Header: {desc} ({value})")

        # Check for common device management interfaces
        mgmt_patterns = [
            ('web management', 'Web Management Interface'),
            ('configuration', 'Configuration Interface'),
            ('admin panel', 'Admin Panel'),
            ('device manager', 'Device Manager'),
            ('network settings', 'Network Settings'),
            ('wireless settings', 'Wireless Settings'),
        ]

        for pattern, name in mgmt_patterns:
            if pattern in content_lower:
                signatures.append(f"Interface: {name}")

    except Exception:
        pass

    return signatures
