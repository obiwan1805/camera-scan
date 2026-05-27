"""HTTPS fingerprint module with SSL handling."""
import asyncio
import ssl
import re
from typing import Optional, Set, Tuple
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint, ProbeResult, RawResponse
from src.layers.layer2_fingerprinter.modules.header_parser import detect_vendor_from_headers, extract_model_from_headers
from src.layers.layer2_fingerprinter.modules.html_parser import detect_vendor_from_html, extract_model_from_html, extract_version_from_html
import aiohttp


class HTTPSModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[ProbeResult]:
        raw_responses = []
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=3)
            ) as session:
                if vendor_hint == "hikvision":
                    result = await self._hikvision_probe(ip, port, session, raw_responses, vendor_hint=True)
                    if result:
                        return result
                elif vendor_hint == "dahua":
                    result = await self._dahua_probe(ip, port, session, raw_responses, vendor_hint=True)
                    if result:
                        return result

                result = await self._basic_https_probe(ip, port, session, raw_responses, vendor_hint)
                if result:
                    return result

                if not vendor_hint or vendor_hint != "hikvision":
                    result = await self._hikvision_probe(ip, port, session, raw_responses)
                    if result:
                        return result

                if not vendor_hint or vendor_hint != "dahua":
                    result = await self._dahua_probe(ip, port, session, raw_responses)
                    if result:
                        return result

        except Exception:
            pass

        if raw_responses:
            return ProbeResult(fingerprint=None, raw_responses=raw_responses)
        return None

    async def _basic_https_probe(self, ip: str, port: int, session: aiohttp.ClientSession, raw_responses: list, vendor_hint: Optional[str] = None) -> Optional[ProbeResult]:
        try:
            url = f"https://{ip}:{port}"
            async with session.get(url, allow_redirects=False) as resp:
                headers = dict(resp.headers)
                html = None
                if resp.content_length and resp.content_length < 100000:
                    try:
                        html = await resp.text()
                    except Exception:
                        pass

                raw_responses.append(RawResponse(
                    ip=ip, port=port, module="https", endpoint="/",
                    status_code=resp.status,
                    content_type=resp.headers.get("Content-Type"),
                    raw_data=(html or "").encode(errors="replace")
                ))

                vendor = detect_vendor_from_headers(headers)

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

                    server = headers.get("Server", "")
                    if vendor in server.lower():
                        probe_method = "https_server_header"
                        evidence.append(f"matched Server header: {server}")
                        matched_pattern = f"Server header contains '{vendor}'"

                    if vendor:
                        model = extract_model_from_headers(headers, vendor)
                        if model:
                            evidence.append(f"extracted model from headers: {model}")

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

                    return ProbeResult(
                        fingerprint=Fingerprint(
                            vendor=vendor, model=model, version=version,
                            raw_banner=str(headers)[:256], services=["https"],
                            probe_method=probe_method,
                            evidence="; ".join(evidence) if evidence else None,
                            matched_pattern=matched_pattern, endpoint="/"
                        ),
                        raw_responses=list(raw_responses)
                    )
        except Exception:
            pass
        return None

    async def _hikvision_probe(self, ip: str, port: int, session: aiohttp.ClientSession, raw_responses: list, vendor_hint: Optional[bool] = None) -> Optional[ProbeResult]:
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

                        raw_responses.append(RawResponse(
                            ip=ip, port=port, module="https", endpoint=path,
                            status_code=resp.status,
                            content_type=resp.headers.get("Content-Type"),
                            raw_data=content.encode(errors="replace")
                        ))

                        if '<deviceInfo>' in content or '<DeviceInfo>' in content:
                            vendor = "hikvision"
                            model, model_pattern = self._extract_hikvision_model(content)
                            version, version_pattern = self._extract_hikvision_version(content)

                            evidence = []
                            if model:
                                evidence.append(f"matched XML pattern: {model_pattern} -> {model}")
                            if version:
                                evidence.append(f"matched XML pattern: {version_pattern} -> {version}")

                            return ProbeResult(
                                fingerprint=Fingerprint(
                                    vendor=vendor, model=model, version=version,
                                    raw_banner=content[:256], services=["https"],
                                    probe_method=probe_type,
                                    evidence="; ".join(evidence) if evidence else f"matched Hikvision XML endpoint: {path}",
                                    matched_pattern=model_pattern or version_pattern,
                                    endpoint=path
                                ),
                                raw_responses=list(raw_responses)
                            )

                        html_vendor = detect_vendor_from_html(content)
                        if html_vendor == "hikvision":
                            model = extract_model_from_html(content, "hikvision")
                            version = extract_version_from_html(content)

                            evidence = [f"detected Hikvision in HTML: {html_vendor}"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return ProbeResult(
                                fingerprint=Fingerprint(
                                    vendor="hikvision", model=model, version=version,
                                    raw_banner=content[:256], services=["https"],
                                    probe_method="hikvision_html_content",
                                    evidence="; ".join(evidence), endpoint=path
                                ),
                                raw_responses=list(raw_responses)
                            )
            except Exception:
                pass
        return None

    async def _dahua_probe(self, ip: str, port: int, session: aiohttp.ClientSession, raw_responses: list, vendor_hint: Optional[bool] = None) -> Optional[ProbeResult]:
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

                        raw_responses.append(RawResponse(
                            ip=ip, port=port, module="https", endpoint=path,
                            status_code=resp.status,
                            content_type=resp.headers.get("Content-Type"),
                            raw_data=content.encode(errors="replace")
                        ))

                        html_vendor = detect_vendor_from_html(content)
                        if html_vendor == "dahua":
                            model = extract_model_from_html(content, "dahua")
                            version = extract_version_from_html(content)

                            evidence = [f"detected Dahua in HTML title: {html_vendor}"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return ProbeResult(
                                fingerprint=Fingerprint(
                                    vendor="dahua", model=model, version=version,
                                    raw_banner=content[:256], services=["https"],
                                    probe_method=probe_type,
                                    evidence="; ".join(evidence), endpoint=path
                                ),
                                raw_responses=list(raw_responses)
                            )
            except Exception:
                pass
        return None

    def _extract_hikvision_model(self, content: str) -> Tuple[Optional[str], Optional[str]]:
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
