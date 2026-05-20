"""Favicon fingerprint module using MMH3 hash for quick vendor identification."""
import asyncio
import aiohttp
import mmh3
import ssl
from typing import Optional, Set
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint

# Favicon MMH3 hash signatures
# Add your known signatures here
FAVICON_HASHES = {
    -1466785234: "dahua",
    2019488876: "dahua",
    1653394551: "dahua",
    999357577: "hikvision",
}

###
# Hikvision:		999357577
# Dahua:			-1466785234, 2019488876, 1653394551
###

# Fallback paths to try if /favicon.ico doesn't exist
FAVICON_PATHS = [
    "/favicon.ico",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/img/favicon.ico",
    "/favicon.png",
]


class FaviconModule(ProtocolModule):
    """Quick vendor identification using favicon MMH3 hashing."""

    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        """Probe for favicon and identify vendor by MMH3 hash."""
        # If we already have a vendor hint, no need to probe
        if vendor_hint:
            return None

        # Try HTTP first, then HTTPS
        for protocol in ["http", "https"]:
            result = await self._probe_protocol(ip, port, protocol)
            if result:
                return result

        return None

    async def _probe_protocol(self, ip: str, port: int, protocol: str) -> Optional[Fingerprint]:
        """Probe favicon using HTTP or HTTPS."""
        try:
            connector = None
            if protocol == "https":
                # Create SSL context that doesn't verify certificates (common in cameras)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                connector = aiohttp.TCPConnector(ssl=ssl_context)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=3)
            ) as session:
                for path in FAVICON_PATHS:
                    result = await self._get_favicon_hash(ip, port, path, protocol, session)
                    if result:
                        return result

        except Exception:
            pass
        return None

    async def _get_favicon_hash(
        self,
        ip: str,
        port: int,
        path: str,
        protocol: str,
        session: aiohttp.ClientSession
    ) -> Optional[Fingerprint]:
        """Download favicon and compute MMH3 hash."""
        try:
            url = f"{protocol}://{ip}:{port}{path}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    # Limit size to 10KB to avoid processing large images
                    if resp.content_length and resp.content_length > 10240:
                        return None

                    data = await resp.read()
                    if len(data) > 10240:
                        return None

                    # Compute MMH3 hash
                    hash_value = mmh3.hash(data)

                    # Look up vendor
                    vendor = FAVICON_HASHES.get(hash_value)

                    if vendor:
                        return Fingerprint(
                            vendor=vendor,
                            probe_method="favicon_mmh3_hash",
                            evidence=f"matched MMH3 hash {hash_value} → {vendor}",
                            matched_pattern=str(hash_value),
                            endpoint=path,
                            services=[protocol]
                        )

        except Exception:
            pass
        return None

    def supported_ports(self) -> Set[int]:
        return {80, 443, 8080, 8443}