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

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._https_session: Optional[aiohttp.ClientSession] = None

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._timeout)
            )
        return self._http_session

    async def _get_https_session(self) -> aiohttp.ClientSession:
        if self._https_session is None or self._https_session.closed:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ctx)
            self._https_session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            )
        return self._https_session

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        for get_session in [self._get_http_session, self._get_https_session]:
            await self._probe_protocol(ip, port, get_session, collected)
            if collected.favicon_hash is not None:
                break
        return collected

    async def _probe_protocol(
        self, ip: str, port: int, get_session, collected: CollectedData
    ) -> None:
        try:
            session = await get_session()
            for path in _FAVICON_PATHS:
                result = await self._get_favicon(ip, port, path, session, collected)
                if result:
                    return
        except Exception:
            pass

    async def _get_favicon(
        self, ip: str, port: int, path: str, session: aiohttp.ClientSession,
        collected: CollectedData
    ) -> bool:
        try:
            protocol = "https" if session is self._https_session else "http"
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

    async def close(self) -> None:
        for session in (self._http_session, self._https_session):
            if session and not session.closed:
                await session.close()
        self._http_session = None
        self._https_session = None
