"""Favicon prober -- computes MMH3 hash of favicon for vendor identification."""
from typing import Optional, Set
import aiohttp
import mmh3
import ssl
from .base import Prober
from .types import CollectedData
from src.storage.schemas import RawResponse

_FAVICON_PATHS = [
    "/favicon.ico",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/img/favicon.ico",
    "/favicon.png",
]


class FaviconProber(Prober):
    """Collects favicon MMH3 hash for signature matching."""

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        for protocol in ["http", "https"]:
            await self._probe_protocol(ip, port, protocol, collected)
            if collected.favicon_hash is not None:
                break
        return collected

    async def _probe_protocol(
        self, ip: str, port: int, protocol: str, collected: CollectedData
    ) -> None:
        try:
            connector = None
            if protocol == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                connector = aiohttp.TCPConnector(ssl=ctx)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=3)
            ) as session:
                for path in _FAVICON_PATHS:
                    result = await self._get_favicon(ip, port, path, protocol, session, collected)
                    if result:
                        return
        except Exception:
            pass

    async def _get_favicon(
        self, ip: str, port: int, path: str, protocol: str,
        session: aiohttp.ClientSession, collected: CollectedData
    ) -> bool:
        try:
            url = f"{protocol}://{ip}:{port}{path}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    collected.raw_responses.append(RawResponse(
                        ip=ip, port=port, module="favicon", endpoint=path,
                        status_code=resp.status,
                        raw_data=b""
                    ))
                    return False

                if resp.content_length and resp.content_length > 10240:
                    return False

                data = await resp.read()
                if len(data) > 10240:
                    return False

                collected.raw_responses.append(RawResponse(
                    ip=ip, port=port, module="favicon", endpoint=path,
                    status_code=resp.status,
                    content_type=resp.headers.get("Content-Type"),
                    raw_data=data
                ))

                hash_value = mmh3.hash(data)
                collected.favicon_hash = hash_value
                return True

        except Exception:
            pass
        return False

    def supported_ports(self) -> Set[int]:
        return {80, 443, 8080, 8443}
