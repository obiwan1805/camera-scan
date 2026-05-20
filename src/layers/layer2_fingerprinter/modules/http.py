"""HTTP fingerprint module with enhanced vendor detection."""
import asyncio
import re
from typing import Optional, Set, Tuple
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint
from src.layers.layer2_fingerprinter.modules.header_parser import detect_vendor_from_headers, extract_model_from_headers
from src.layers.layer2_fingerprinter.modules.html_parser import detect_vendor_from_html, extract_model_from_html, extract_version_from_html
import aiohttp


class HTTPModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
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
                # Stage 1: Basic HTTP GET
                result = await self._basic_http_probe(ip, port, session, vendor_hint)
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

    async def _basic_http_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        try:
            url = f"http://{ip}:{port}"
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
                        probe_method = "http_server_header"
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
                        probe_method = "http_html_content"
                        evidence.append(f"detected vendor in HTML content: {vendor}")

                    return Fingerprint(
                        vendor=vendor,
                        model=model,
                        version=version,
                        raw_banner=str(headers)[:256],
                        services=["http"],
                        probe_method=probe_method,
                        evidence="; ".join(evidence) if evidence else None,
                        matched_pattern=matched_pattern,
                        endpoint="/"
                    )
        except Exception:
            pass
        return None

    async def _hikvision_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[bool] = None) -> Optional[Fingerprint]:
        """Hikvision-specific probing with enhanced version detection."""
        paths = [
            # XML endpoints
            ('/ISAPI/System/deviceInfo', 'xml_endpoint'),
            ('/ISAPI/System/firmwareInfo', 'xml_endpoint'),
            ('/ISAPI/System/serialNumber', 'xml_endpoint'),
            ('/ISAPI/Time/time', 'xml_endpoint'),
            ('/docu/page.xml', 'xml_endpoint'),
            ('/PSIA/System/deviceInfo', 'xml_endpoint'),
            ('/ISAPI/ContentMgmt/download', 'xml_endpoint'),
            ('/System/upgradeFirmware', 'xml_endpoint'),
            # Other potential endpoints
            ('/ISAPI/Security/users/checkUser', 'xml_endpoint'),
            ('/version', 'xml_endpoint'),
            ('/ISAPI/Streaming/channels', 'xml_endpoint'),
        ]

        for path, probe_type in paths:
            try:
                url = f"http://{ip}:{port}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        content = await resp.text()

                        # Stage 1: Parse XML for device info
                        vendor = "hikvision"
                        model, model_pattern = self._extract_hikvision_model(content)
                        version, version_pattern = self._extract_hikvision_version(content)

                        evidence = []
                        if model:
                            evidence.append(f"matched XML pattern: {model_pattern} -> {model}")
                        if version:
                            evidence.append(f"matched XML pattern: {version_pattern} -> {version}")

                        if model or version:
                            return Fingerprint(
                                vendor=vendor,
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["http"],
                                probe_method=probe_type,
                                evidence="; ".join(evidence) if evidence else f"matched Hikvision endpoint: {path}",
                                matched_pattern=model_pattern or version_pattern,
                                endpoint=path
                            )

                        # Stage 2: Parse HTML for version patterns
                        html_vendor = detect_vendor_from_html(content)
                        if html_vendor == "hikvision":
                            if not model:
                                model = extract_model_from_html(content, "hikvision")
                            if not version:
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
                                services=["http"],
                                probe_method="hikvision_html_content",
                                evidence="; ".join(evidence),
                                endpoint=path
                            )

                        # Stage 3: Parse for CSS/JS version patterns
                        version, asset_pattern = self._extract_version_from_assets(content)
                        if version:
                            model = extract_model_from_html(content, "hikvision")
                            evidence = [f"matched asset pattern: {asset_pattern} -> {version}"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")

                            return Fingerprint(
                                vendor="hikvision",
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["http"],
                                probe_method="hikvision_asset_version",
                                evidence="; ".join(evidence),
                                matched_pattern=asset_pattern,
                                endpoint=path
                            )
            except Exception:
                pass
        return None

    async def _dahua_probe(self, ip: str, port: int, session: aiohttp.ClientSession, vendor_hint: Optional[bool] = None) -> Optional[Fingerprint]:
        """Dahua-specific probing with enhanced version detection."""
        paths = [
            # RPC2 endpoints (XML-RPC)
            ('/RPC2_Login', 'xml_rpc'),
            ('/RPC2', 'xml_rpc'),
            ('/RPC2_Login?action=login', 'xml_rpc'),
            # Config manager endpoints
            ('/cgi-bin/configManager.cgi?action=getConfig&name=SystemInfo', 'cgi_endpoint'),
            ('/cgi-bin/configManager.cgi?action=getConfig&name=NetWork.Common', 'cgi_endpoint'),
            ('/cgi-bin/configManager.cgi?action=getConfig&name=System.General', 'cgi_endpoint'),
            ('/cgi-bin/magicBox.cgi?action=getSystemInfo', 'cgi_endpoint'),
            ('/cgi-bin/magicBox.cgi?action=getSystemInfo&date=0', 'cgi_endpoint'),
            # JSON endpoints
            ('/config/system', 'json_endpoint'),
            ('/RPC2_Login?action=getSystemInfo', 'xml_rpc'),
            ('/cgi-bin/configManager.cgi?action=getConfig&name=System.SerialNumber', 'cgi_endpoint'),
        ]

        for path, probe_type in paths:
            try:
                url = f"http://{ip}:{port}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        content = await resp.text()

                        # Stage 1: Check for XML-RPC response
                        if '<methodResponse>' in content or '<?xml' in content:
                            vendor = "dahua"
                            model, model_pattern = self._extract_dahua_model_from_rpc(content)
                            version, version_pattern = self._extract_dahua_version_from_rpc(content)

                            evidence = []
                            if model:
                                evidence.append(f"matched XML-RPC pattern: {model_pattern} -> {model}")
                            if version:
                                evidence.append(f"matched XML-RPC pattern: {version_pattern} -> {version}")

                            if model or version:
                                return Fingerprint(
                                    vendor=vendor,
                                    model=model,
                                    version=version,
                                    raw_banner=content[:256],
                                    services=["http"],
                                    probe_method=probe_type,
                                    evidence="; ".join(evidence) if evidence else f"matched XML-RPC response: {path}",
                                    matched_pattern=model_pattern or version_pattern,
                                    endpoint=path
                                )

                        # Stage 2: Parse JSON response
                        if '{' in content and '}' in content:
                            vendor = "dahua"
                            model, model_pattern = self._extract_dahua_model_from_json(content)
                            version, version_pattern = self._extract_dahua_version_from_json(content)

                            evidence = []
                            if model:
                                evidence.append(f"matched JSON key: {model_pattern} -> {model}")
                            if version:
                                evidence.append(f"matched JSON key: {version_pattern} -> {version}")

                            if model or version:
                                return Fingerprint(
                                    vendor=vendor,
                                    model=model,
                                    version=version,
                                    raw_banner=content[:256],
                                    services=["http"],
                                    probe_method=probe_type,
                                    evidence="; ".join(evidence) if evidence else f"matched JSON response: {path}",
                                    matched_pattern=model_pattern or version_pattern,
                                    endpoint=path
                                )

                        # Stage 3: Check HTML title
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
                                services=["http"],
                                probe_method="dahua_html_title",
                                evidence="; ".join(evidence),
                                endpoint=path
                            )

                        # Stage 4: Check for Dahua-specific response patterns
                        if "Dahua" in content or "DAHUA" in content or "dahua" in content:
                            model = extract_model_from_html(content, "dahua")
                            version = extract_version_from_html(content)

                            evidence = [f"matched 'Dahua' in response content"]
                            if model:
                                evidence.append(f"extracted model from HTML: {model}")
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return Fingerprint(
                                vendor="dahua",
                                model=model,
                                version=version,
                                raw_banner=content[:256],
                                services=["http"],
                                probe_method="dahua_content_pattern",
                                evidence="; ".join(evidence),
                                endpoint=path
                            )

                        # Stage 5: Check for IPC-HFW/IPC-HDBW patterns
                        dahua_model, model_pattern = self._extract_dahua_model_from_content(content)
                        if dahua_model:
                            version = extract_version_from_html(content)
                            evidence = [f"matched model pattern: {model_pattern} -> {dahua_model}"]
                            if version:
                                evidence.append(f"extracted version from HTML: {version}")

                            return Fingerprint(
                                vendor="dahua",
                                model=dahua_model,
                                version=version,
                                raw_banner=content[:256],
                                services=["http"],
                                probe_method="dahua_model_pattern",
                                evidence="; ".join(evidence),
                                matched_pattern=model_pattern,
                                endpoint=path
                            )
            except Exception:
                pass
        return None

    def _extract_dahua_model_from_rpc(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract model from Dahua XML-RPC response. Returns (model, pattern)."""
        patterns = [
            (r'<string>(IPC-HFW\d+[A-Za-z\d-]*)</string>', 'IPC-HFW'),
            (r'<string>(IPC-HDBW\d+[A-Za-z\d-]*)</string>', 'IPC-HDBW'),
            (r'<string>(IPC-HDW\d+[A-Za-z\d-]*)</string>', 'IPC-HDW'),
            (r'<string>(IPC-HDB\d+[A-Za-z\d-]*)</string>', 'IPC-HDB'),
            (r'<string>(SD\d+[A-Za-z\d-]*)</string>', 'SD'),
            (r'<string>(NVR\d+[A-Za-z\d-]*)</string>', 'NVR'),
            (r'<string>(XVR\d+[A-Za-z\d-]*)</string>', 'XVR'),
            (r'<name>([^<]+)</name>', 'name'),
            (r'<model>([^<]+)</model>', 'model'),
            (r'<Model>([^<]+)</Model>', 'Model'),
            (r'<deviceModel>([^<]+)</deviceModel>', 'deviceModel'),
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content)
            if match:
                model = match.group(1).strip()
                # Filter out non-model strings
                if any(x in model.upper() for x in ['IPC', 'NVR', 'XVR', 'SD', 'HCVR']):
                    return model, pattern_name
        return None, None

    def _extract_dahua_version_from_rpc(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract version from Dahua XML-RPC response. Returns (version, pattern)."""
        patterns = [
            (r'<string>(V\d+\.\d+\.\d+[^<]*)</string>', 'V version'),
            (r'<string>(v\d+\.\d+\.\d+[^<]*)</string>', 'v version'),
            (r'<firmwareVersion>([^<]+)</firmwareVersion>', 'firmwareVersion'),
            (r'<FirmwareVersion>([^<]+)</FirmwareVersion>', 'FirmwareVersion'),
            (r'<version>([^<]+)</version>', 'version'),
            (r'<Version>([^<]+)</Version>', 'Version'),
            (r'<softwareVersion>([^<]+)</softwareVersion>', 'softwareVersion'),
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                # Clean up and format
                version = re.sub(r'[<>\r\n]', '', version)
                if version and re.search(r'\d+\.\d+', version):
                    return version.upper() if not version.startswith('V') else version, pattern_name
        return None, None

    def _extract_dahua_model_from_json(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract model from Dahua JSON response. Returns (model, pattern)."""
        try:
            import json
            data = json.loads(content)

            # Try various keys that might contain model info
            model_keys = ['model', 'Model', 'deviceModel', 'DeviceModel', 'deviceName', 'DeviceName']
            for key in model_keys:
                if key in data:
                    model = str(data[key])
                    if any(x in model.upper() for x in ['IPC', 'NVR', 'XVR', 'SD', 'HCVR']):
                        return model, f"JSON key: {key}"
        except Exception:
            pass

        # Fallback to regex patterns in JSON string
        patterns = [
            (r'"model"\s*:\s*"([^"]+)"', '"model"'),
            (r'"Model"\s*:\s*"([^"]+)"', '"Model"'),
            (r'"deviceModel"\s*:\s*"([^"]+)"', '"deviceModel"'),
            (r'"deviceName"\s*:\s*"([^"]+)"', '"deviceName"'),
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content)
            if match:
                model = match.group(1)
                if any(x in model.upper() for x in ['IPC', 'NVR', 'XVR', 'SD', 'HCVR']):
                    return model, f"JSON pattern: {pattern_name}"
        return None, None

    def _extract_dahua_version_from_json(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract version from Dahua JSON response. Returns (version, pattern)."""
        try:
            import json
            data = json.loads(content)

            # Try various keys that might contain version info
            version_keys = ['firmwareVersion', 'FirmwareVersion', 'version', 'Version', 'softwareVersion', 'SoftwareVersion']
            for key in version_keys:
                if key in data:
                    version = str(data[key])
                    if re.search(r'\d+\.\d+', version):
                        return version.upper() if not version.startswith('V') else f"V{version}", f"JSON key: {key}"
        except Exception:
            pass

        # Fallback to regex patterns in JSON string
        patterns = [
            (r'"firmwareVersion"\s*:\s*"([^"]+)"', '"firmwareVersion"'),
            (r'"FirmwareVersion"\s*:\s*"([^"]+)"', '"FirmwareVersion"'),
            (r'"version"\s*:\s*"([^"]+)"', '"version"'),
            (r'"Version"\s*:\s*"([^"]+)"', '"Version"'),
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                if re.search(r'\d+\.\d+', version):
                    return version.upper() if not version.startswith('V') else f"V{version}", f"JSON pattern: {pattern_name}"
        return None, None

    def _extract_dahua_model_from_content(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract Dahua model from content using pattern matching. Returns (model, pattern)."""
        # Remove base64 data sections to avoid false positives from favicon images
        content_no_base64 = re.sub(r'(?:base64,|data:)[A-Za-z0-9+/=]+', '', content)

        patterns = [
            (r'IPC-HFW\d+[A-Za-z\d-]*', 'IPC-HFW pattern'),
            (r'IPC-HDBW\d+[A-Za-z\d-]*', 'IPC-HDBW pattern'),
            (r'IPC-HDW\d+[A-Za-z\d-]*', 'IPC-HDW pattern'),
            (r'IPC-HDB\d+[A-Za-z\d-]*', 'IPC-HDB pattern'),
            (r'IPC-HFW\d+\w+', 'IPC-HFW short'),
            # SD pattern: must be followed by at least 4 digits (typical Dahua SD model format)
            (r'\bSD\d{4,}[A-Za-z\d-]*\b', 'SD pattern'),
            (r'NVR\d+[A-Za-z\d-]*', 'NVR pattern'),
            (r'XVR\d+[A-Za-z\d-]*', 'XVR pattern'),
            (r'HCVR\d+[A-Za-z\d-]*', 'HCVR pattern'),
            (r'DH-IPC-[A-Za-z\d-]+', 'DH-IPC pattern'),
            (r'DH-NVR-[A-Za-z\d-]+', 'DH-NVR pattern'),
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content_no_base64, re.IGNORECASE)
            if match:
                return match.group(0).upper(), pattern_name
        return None, None

    def _extract_hikvision_model(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract model from Hikvision device info XML. Returns (model, pattern)."""
        patterns = [
            (r'<model>(.*?)</model>', '<model>'),
            (r'<Model>(.*?)</Model>', '<Model>'),
            (r'<deviceModel>(.*?)</deviceModel>', '<deviceModel>'),
            (r'<deviceName>(.*?)</deviceName>', '<deviceName>'),
            (r'DS-2CD\d+[A-Za-z\d-]*', 'DS-2CD pattern'),
            (r'DS-2TD\d+[A-Za-z\d-]*', 'DS-2TD pattern')
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip(), pattern_name
        return None, None

    def _extract_hikvision_version(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract version from Hikvision device info XML. Returns (version, pattern)."""
        # XML element patterns (safe - won't match XML declaration)
        xml_patterns = [
            (r'<firmwareVersion>(.*?)</firmwareVersion>', '<firmwareVersion>'),
            (r'<FirmwareVersion>(.*?)</FirmwareVersion>', '<FirmwareVersion>'),
            (r'<softwareVersion>(.*?)</softwareVersion>', '<softwareVersion>'),
            (r'<SoftwareVersion>(.*?)</SoftwareVersion>', '<SoftwareVersion>'),
            (r'<version>(.*?)</version>', '<version>'),
            (r'<Version>(.*?)</Version>', '<Version>'),
        ]

        for pattern, pattern_name in xml_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                version = match.group(1).strip()
                # Skip XML standard versions (1.0, 1.1 are XML declaration versions)
                if version not in ['1.0', '1.1']:
                    return version if version.startswith("V") else f"V{version}", pattern_name

        # Version string patterns in content (careful not to match XML declaration)
        version_patterns = [
            (r'V\d+\.\d+\.\d+[\w\s.-]*', 'Vx.x.x'),
            (r'v\d+\.\d+\.\d+[\w\s.-]*', 'vx.x.x'),
        ]

        # Skip first line if it's XML declaration
        content_without_decl = re.sub(r'<\?xml[^>]*\?>', '', content, count=1)

        for pattern, pattern_name in version_patterns:
            match = re.search(pattern, content_without_decl, re.IGNORECASE)
            if match:
                version = match.group(0).strip()
                version = re.sub(r'[^vV\d.]', '', version)
                # Skip XML standard versions
                if version not in ['V1.0', 'V1.1', '1.0', '1.1']:
                    return version if version.startswith("V") else f"V{version}", pattern_name

        return None, None

    def _extract_version_from_assets(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract version from CSS/JS files. Returns (version, pattern)."""
        # Look for version patterns in href/src attributes
        version_patterns = [
            (r'href=["\'][^"\']*css["\']?v=(\d+\.\d+)[^"\']*["\']?', 'href v='),
            (r'src=["\'][^"\']*js["\']?v=(\d+\.\d+)[^"\']*["\']?', 'src v='),
            (r'/common/css/main\.css\?v=(\d+\.\d+)', 'main.css v='),
            (r'/common/js/common\.js\?v=(\d+\.\d+)', 'common.js v='),
            (r'var firmware["\s]*=["\']([^"\']+)[""\']', 'var firmware'),
            (r'var version["\s]*=["\']([^"\']+)[""\']', 'var version'),
        ]

        for pattern, pattern_name in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                version = re.sub(r'[^vV\d.]', '', version)
                return version if version.startswith("V") else f"V{version}", pattern_name

        return None, None

    def supported_ports(self) -> Set[int]:
        return {80, 8080, 8000, 8888}