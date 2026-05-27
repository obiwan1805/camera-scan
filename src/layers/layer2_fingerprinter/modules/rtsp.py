"""RTSP fingerprint module with enhanced vendor detection."""
import asyncio
import re
from typing import Optional, Set, Tuple
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint, ProbeResult, RawResponse


class RTSPModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[ProbeResult]:
        raw_responses = []

        for path in ['/stream1', '/cam/realmonitor', '/h264/ch1/main/av_stream', '/']:
            result = await self._rtsp_describe(ip, port, path, vendor_hint, raw_responses)
            if result:
                return result

        result = await self._rtsp_options(ip, port, vendor_hint, raw_responses)
        if result:
            return result

        if raw_responses:
            return ProbeResult(fingerprint=None, raw_responses=raw_responses)
        return None

    async def _rtsp_describe(self, ip: str, port: int, path: str, vendor_hint: Optional[str], raw_responses: list) -> Optional[ProbeResult]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )

            request = f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: RTSP Client\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            raw_responses.append(RawResponse(
                ip=ip, port=port, module="rtsp", endpoint=path,
                raw_data=response
            ))

            response_str = response.decode(errors="ignore")
            if response_str:
                fp = self._parse_rtsp_response(response_str, method="rtsp_describe", endpoint=path)
                if fp:
                    return ProbeResult(fingerprint=fp, raw_responses=list(raw_responses))

        except Exception:
            pass
        return None

    async def _rtsp_options(self, ip: str, port: int, vendor_hint: Optional[str], raw_responses: list) -> Optional[ProbeResult]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )

            request = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: RTSP Client\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            response = await reader.read(512)
            writer.close()
            await writer.wait_closed()

            raw_responses.append(RawResponse(
                ip=ip, port=port, module="rtsp", endpoint="/",
                raw_data=response
            ))

            response_str = response.decode(errors="ignore")
            if response_str:
                fp = self._parse_rtsp_response(response_str, method="rtsp_options", endpoint="/")
                if fp:
                    return ProbeResult(fingerprint=fp, raw_responses=list(raw_responses))

        except Exception:
            pass
        return None

    def _parse_rtsp_response(self, response: str, method: str, endpoint: str) -> Optional[Fingerprint]:
        """Parse RTSP response for vendor information."""
        if not response.startswith("RTSP/1.0") and not response.startswith("RTSP/1.1"):
            return None

        vendor_patterns = {
            "hikvision": [
                (r"Hikvision", "Hikvision"),
                (r"HIKVISION", "HIKVISION"),
                (r"RTSP/1.0.*Hikvision", "RTSP/1.0 Hikvision"),
                (r"Server:.*Hikvision", "Server: Hikvision")
            ],
            "dahua": [
                (r"Dahua", "Dahua"),
                (r"DAHUA", "DAHUA"),
                (r"DVR WEB CLIENT", "DVR WEB CLIENT"),
                (r"DahuaTech", "DahuaTech")
            ],
            "axis": [
                (r"Axis", "Axis"),
                (r"axis", "axis"),
                (r"AXIS", "AXIS")
            ],
            "foscam": [
                (r"Foscam", "Foscam"),
                (r"foscam", "foscam")
            ],
            "vivotek": [
                (r"Vivotek", "Vivotek"),
                (r"vivotek", "vivotek"),
                (r"VIVOTEK", "VIVOTEK")
            ],
            "sony": [
                (r"Sony", "Sony"),
                (r"SONY", "SONY")
            ],
            "panasonic": [
                (r"Panasonic", "Panasonic"),
                (r"panasonic", "panasonic"),
                (r"WV-", "WV-")
            ],
            "ubiquiti": [
                (r"Ubiquiti", "Ubiquiti"),
                (r"ubiquiti", "ubiquiti"),
                (r"UniFi", "UniFi")
            ]
        }

        vendor = None
        matched_pattern = None

        for vendor_name, patterns in vendor_patterns.items():
            for pattern, pattern_name in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    vendor = vendor_name
                    matched_pattern = pattern_name
                    break
            if vendor:
                break

        if vendor:
            model, model_pattern = self._extract_model_from_rtsp(response)
            version, version_pattern = self._extract_version_from_rtsp(response)

            evidence = [f"matched RTSP pattern: {matched_pattern}"]
            if model:
                evidence.append(f"extracted model: {model} (pattern: {model_pattern})")
            if version:
                evidence.append(f"extracted version: {version} (pattern: {version_pattern})")

            return Fingerprint(
                vendor=vendor,
                model=model,
                version=version,
                raw_banner=response[:256],
                services=["rtsp"],
                probe_method=method,
                evidence="; ".join(evidence),
                matched_pattern=matched_pattern,
                endpoint=endpoint
            )

        return None

    def _extract_model_from_rtsp(self, response: str) -> Tuple[Optional[str], Optional[str]]:
        patterns = [
            (r'DS-2CD\d+[A-Za-z\d-]*', 'DS-2CD'),
            (r'IPC-HFW\d+[A-Za-z\d-]*', 'IPC-HFW'),
            (r'IPC-HDBW\d+[A-Za-z\d-]*', 'IPC-HDBW'),
            (r'Q\d+[A-Za-z\d-]*', 'Q series'),
            (r'FD\d+[A-Za-z\d-]*', 'FD series'),
            (r'SNC-\w+', 'SNC'),
            (r'WV-\w+', 'WV')
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, response)
            if match:
                return match.group(0), pattern_name
        return None, None

    def _extract_version_from_rtsp(self, response: str) -> Tuple[Optional[str], Optional[str]]:
        patterns = [
            (r'V\d+\.\d+\.\d+', 'Vx.x.x'),
            (r'v\d+\.\d+\.\d+', 'vx.x.x'),
            (r'version[=:]\s*(\d+\.\d+\.\d+)', 'version='),
            (r'firmware[=:]\s*(\d+\.\d+\.\d+)', 'firmware=')
        ]
        for pattern, pattern_name in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                return version.upper() if version.startswith("V") else f"V{version}", pattern_name
        return None, None

    def supported_ports(self) -> Set[int]:
        return {554, 8554, 10554}
