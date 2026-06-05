"""ONVIF prober -- collects SOAP GetDeviceInformation responses."""
import asyncio
import ssl
from typing import Set
from .base import Prober
from .types import CollectedData
from src.storage.schemas import RawResponse
from src.utils.logging import setup_logger

_ONVIF_ENDPOINTS = [
    "/onvif/device_service",
    "/onvif/device",
    "/onvif/Device",
    "/device_service",
]

_SOAP_REQUEST = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>'''


class ONVIFProber(Prober):
    """Collects ONVIF SOAP GetDeviceInformation responses."""

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._logger = setup_logger("ONVIFProber")

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        for endpoint in _ONVIF_ENDPOINTS:
            result = await self._try_onvif(ip, port, endpoint, collected, use_ssl=False)
            if result:
                return collected

        # Try HTTPS ONVIF if HTTP didn't work
        for endpoint in _ONVIF_ENDPOINTS:
            result = await self._try_onvif(ip, port, endpoint, collected, use_ssl=True)
            if result:
                return collected

        return collected

    async def _try_onvif(
        self, ip: str, port: int, endpoint: str, collected: CollectedData,
        use_ssl: bool = False,
    ) -> bool:
        try:
            ssl_ctx = False
            if use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=self._timeout
            )

            soap = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"Content-Type: text/xml; charset=utf-8\r\n"
                f"Content-Length: {len(_SOAP_REQUEST)}\r\n"
                f"Connection: close\r\n"
                f'SOAPAction: "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"\r\n'
                f"\r\n"
                f"{_SOAP_REQUEST}"
            )

            writer.write(soap.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=self._timeout)
            writer.close()
            await writer.wait_closed()

            collected.raw_responses.append(RawResponse(
                ip=ip, port=port, module="onvif", endpoint=endpoint,
                raw_data=response
            ))

            response_str = response.decode(errors="ignore")
            if "GetDeviceInformationResponse" in response_str:
                parts = response_str.split("\r\n\r\n", 1)
                body = parts[1] if len(parts) > 1 else response_str
                collected.onvif_response = body
                return True

        except Exception:
            pass
        return False

    def supported_ports(self) -> Set[int]:
        return {80, 443, 8080, 8000, 8443}
