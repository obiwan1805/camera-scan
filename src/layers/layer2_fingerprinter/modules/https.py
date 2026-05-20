"""HTTPS fingerprint module with SSL handling."""
import asyncio
import ssl
import re
from typing import Optional, Set, Tuple
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint
from src.layers.layer2_fingerprinter.modules.header_parser import detect_vendor_from_headers, extract_model_from_headers
from src.layers.layer2_fingerprinter.modules.html_parser import detect_vendor_from_html, extract_model_from_html, extract_version_from_html
import aiohttp


class HTTPSModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        try:
            # Create SSL context that doesn't verify certificates (common in cameras)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=3)
            ) as session:
                # If we have a vendor hint, go directly to vendor-specific probing
                if vendor_hint == "hikvision":
                    result = await self._hikvision_probe(ip, port, session, vendor_hint=True)
                    if result:
                        return result
                elif vendor_hint == "dahua":
                    result = await self._dahua_probe(ip, port, session, vendor_hint=True)
                    if result:
                        return result

                # No vendor hint or vendor didn't match - try standard probing
                # Stage 1: Basic HTTPS GET
                result = await self._basic_https_probe(ip, port, session, vendor_hint)
                if result:
                    return result

                # Stage 2: Hikvision specific (only if no vendor hint or hint not hikvision)
                if not vendor_hint or vendor_hint != "hikvision":
                    result = await self._hikvision_probe(ip, port, session)
                    if result:
                        return result

                # Stage 3: Dahua specific (only if no vendor hint or hint not dahua)
                if not vendor_hint or vendor_hint != "dahua":
                    result = await self._dahua_probe(ip, port, session)
                    if result:
                        return result

        except Exception:
            pass
        return None

    async def _basic_https_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        try:
            url = f"https://{ip}:{port}"
            async with session.get(url, allow_redirects=False) as resp:
                headers = dict(resp.headers)
                vendor = detect_vendor_from_headers(headers)

                # Try to get HTML content if available
                html = None
                if resp.content_length and resp.content_length < 100000:
                    try:
                        html = await resp.text()
                    except Exception:
                        pass

                # If no vendor from headers, try HTML
                html_vendor = None
                if not vendor and html:
                    html_vendor = detect_vendor_from_html(html)
                    if html_vendor:
                        vendor = html_vendor

                if vendor:
                    model = None
                    version = None
                    evidence = []
                    matched_pattern = None
                    probe_method = None

                    # Check Server header
                    server = headers.get("Server", "")
                    if vendor in server.lower():
                        probe_method = "https_server_header"
                        evidence.append(f"matched Server header: {server}")
                        matched_pattern = f"Server header contains '{vendor}'"

                    # Try to get model from headers
                    if vendor:
                        model = extract_model_from_headers(headers, vendor)
                        if model:
                            evidence.append(f"extracted model from headers: {model}")

                    # Try to get model/version from HTML
                    if html and vendor:
                        if not model:
                            model = extract_model_from_html(html, vendor)
                            if model:
                                evidence.append(f"extracted model from HTML title/content: {model}")
                        version = extract_version_from_html(html)
                        if version:
                            evidence.append(f"extracted version from HTML: {version}")

                    if not probe_method:
                        probe_method = "https_html_content"
                        evidence.append(f"detected vendor in HTML content: {vendor}")

                    return Fingerprint(
                        vendor=vendor,
                        model=model,
                        version=version,
                        raw_banner=str(headers)[:256],
                        services=["https"],
                        probe_method=probe_method,
                        evidence="; ".join(evidence) if evidence else None,
                        matched_pattern=matched_pattern,
                        endpoint="/"
                    )
        except Exception:
            pass
        return None

    async def _hikvision_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[bool] = None) -> Optional[Fingerprint]:
        paths = [
            ('/ISAPI/System/deviceInfo', 'xml_endpoint'),
            ('/docu/page.xml', 'xml_endpoint'),
            ('/PSIA/System/deviceInfo', 'xml_endpoint')
        ]
        for path, probe_type in paths:
            try:
                url = f"https://{ip}:{port}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status == 200:
                        content = await resp.text()

                        # Parse XML response for device info
                        if '<deviceInfo>' in content or '<DeviceInfo>' in content:
                            vendor = "hikvision"
                            model, model_pattern = self._extract_hikvision_model(content)
                            version, version_pattern = self._extract_hikvision_version(content)

                            evidence = []
                            if model:
                                evidence.append(f"matched XML pattern: {model_pattern} -> {model}")
                            if version:
                                evidence.append(f"matched XML pattern: {version_pattern} -> {version}")

                            return Fingerprint(
                                vendor=vendor,
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["https"],
                                probe_method=probe_type,
                                evidence="; ".join(evidence) if evidence else f"matched Hikvision XML endpoint: {path}",
                                matched_pattern=model_pattern or version_pattern,
                                endpoint=path
                            )

                        # Check HTML title
                        html_vendor = detect_vendor_from_html(content)
                        if html_vendor == "hikvision":
                            model = extract_model_from_html(content, "hikvision")
                            version = extract_version_from_html(content)

                            evidence = [f"detected Hikvision in HTML: {html_vendor}"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return Fingerprint(
                                vendor="hikvision",
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["https"],
                                probe_method="hikvision_html_content",
                                evidence="; ".join(evidence),
                                endpoint=path
                            )
            except Exception:
                pass
        return None

    async def _dahua_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[bool] = None) -> Optional[Fingerprint]:
        paths = [
            ('/RPC2_Login', 'xml_rpc'),
            ('/config', 'html_endpoint'),
            ('/cgi-bin/configManager.cgi?action=getConfig&name=NetWork.Common', 'cgi_endpoint')
        ]
        for path, probe_type in paths:
            try:
                url = f"https://{ip}:{port}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status == 200:
                        content = await resp.text()

                        # Check HTML title
                        html_vendor = detect_vendor_from_html(content)
                        if html_vendor == "dahua":
                            model = extract_model_from_html(content, "dahua")
                            version = extract_version_from_html(content)

                            evidence = [f"detected Dahua in HTML title: {html_vendor}"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return Fingerprint(
                                vendor="dahua",
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["https"],
                                probe_method=probe_type,
                                evidence="; ".join(evidence),
                                endpoint=path
                            )
            except Exception:
                pass
        return None

    def _extract_hikvision_model(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract model from Hikvision device info XML. Returns (model, pattern)."""
        patterns = [
            (r'<model>(.*?)</model>', '<model>'),
            (r'<Model>(.*?)</Model>', '<Model>'),
            (r'<deviceModel>(.*?)</deviceModel>', '<deviceModel>'),
            (r'<deviceName>(.*?)</deviceName>', '<deviceName>')
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip(), pattern_name
        return None, None

    def _extract_hikvision_version(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract version from Hikvision device info XML. Returns (version, pattern)."""
        patterns = [
            (r'<firmwareVersion>(.*?)</firmwareVersion>', '<firmwareVersion>'),
            (r'<FirmwareVersion>(.*?)</FirmwareVersion>', '<FirmwareVersion>'),
            (r'<version>(.*?)</version>', '<version>'),
            (r'<Version>(.*?)</Version>', '<Version>')
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                version = match.group(1).strip()
                return version if version.startswith("V") else f"V{version}", pattern_name
        return None, None

    def supported_ports(self) -> Set[int]:
        return {443, 8443, 10443}