"""ONVIF fingerprint module with direct SOAP requests."""
import asyncio
import re
from typing import Optional, Set
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint


class ONVIFModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        endpoints = [
            ('/onvif/device_service', 'onvif_device_service'),
            ('/onvif/device', 'onvif_device'),
            ('/onvif/Device', 'onvif_Device'),
            ('/device_service', 'device_service'),
            ('/device', 'device'),
            ('/', 'root')
        ]

        for endpoint, probe_type in endpoints:
            result = await self._try_onvif(ip, port, endpoint, probe_type, vendor_hint)
            if result:
                return result

        return None

    async def _try_onvif(self, ip: str, port: int, endpoint: str, probe_type: str, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )

            # Send GetDeviceInformation SOAP request
            soap_request = f'''POST {endpoint} HTTP/1.1
Host: {ip}:{port}
Content-Type: text/xml; charset=utf-8
Content-Length: 545
Connection: close
SOAPAction: "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"

<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
'''

            writer.write(soap_request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=3)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode(errors="ignore")

            # Parse SOAP response
            if "GetDeviceInformationResponse" in response_str:
                return self._parse_onvif_response(response_str, endpoint, probe_type)

        except Exception:
            pass
        return None

    def _parse_onvif_response(self, response: str, endpoint: str, probe_type: str) -> Optional[Fingerprint]:
        """Parse ONVIF GetDeviceInformation response."""

        # Extract manufacturer
        manufacturer_match = re.search(r'<(?:tds:)?Manufacturer>([^<]+)</(?:tds:)?Manufacturer>', response)
        manufacturer = manufacturer_match.group(1).strip() if manufacturer_match else None

        # Extract model
        model_match = re.search(r'<(?:tds:)?Model>([^<]+)</(?:tds:)?Model>', response)
        model = model_match.group(1).strip() if model_match else None

        # Extract firmware version
        firmware_match = re.search(r'<(?:tds:)?FirmwareVersion>([^<]+)</(?:tds:)?FirmwareVersion>', response)
        version = firmware_match.group(1).strip() if firmware_match else None

        # Extract serial number
        serial_match = re.search(r'<(?:tds:)?SerialNumber>([^<]+)</(?:tds:)?SerialNumber>', response)

        # Normalize vendor name
        vendor = None
        evidence = []

        if manufacturer:
            manufacturer_lower = manufacturer.lower()
            if "hikvision" in manufacturer_lower:
                vendor = "hikvision"
                evidence.append(f"matched ONVIF Manufacturer: {manufacturer} -> Hikvision")
            elif "dahua" in manufacturer_lower:
                vendor = "dahua"
                evidence.append(f"matched ONVIF Manufacturer: {manufacturer} -> Dahua")
            elif "axis" in manufacturer_lower:
                vendor = "axis"
                evidence.append(f"matched ONVIF Manufacturer: {manufacturer} -> Axis")
            else:
                vendor = manufacturer
                evidence.append(f"detected ONVIF Manufacturer: {manufacturer}")

        if model:
            evidence.append(f"extracted ONVIF Model: {model}")

        if version:
            evidence.append(f"extracted ONVIF FirmwareVersion: {version}")

        if vendor or model or version:
            return Fingerprint(
                vendor=vendor,
                model=model,
                version=version,
                raw_banner=response[:256],
                services=["onvif"],
                probe_method=probe_type,
                evidence="; ".join(evidence) if evidence else "ONVIF GetDeviceInformation response",
                endpoint=endpoint
            )

        return None

    def supported_ports(self) -> Set[int]:
        return {80, 8080, 8000, 8443}