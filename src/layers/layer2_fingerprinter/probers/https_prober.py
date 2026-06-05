"""HTTPS prober -- collects HTML, headers, endpoint responses, and SSL cert info."""
import asyncio
import ssl
from typing import Optional, Set
import aiohttp
from .base import Prober
from .types import CollectedData
from src.storage.schemas import RawResponse


class HTTPSProber(Prober):
    """Collects data via HTTPS with SSL cert extraction."""

    def __init__(self, endpoint_paths: Optional[set[str]] = None, timeout: int = 10):
        self._endpoint_paths = endpoint_paths or set()
        self._timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    def set_endpoints(self, paths: set[str]) -> None:
        self._endpoint_paths = paths

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            )
        return self._session

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        try:
            session = await self._get_session()

            html, headers = await self._fetch_root(ip, port, session, collected)
            if html:
                if not collected.html:
                    collected.html = html
            if headers:
                collected.headers.update(headers)

            await self._extract_ssl_subject(ip, port, collected)

            if self._endpoint_paths:
                await self._fetch_endpoints(ip, port, session, collected)

        except Exception:
            pass

        return collected

    async def _fetch_root(
        self, ip: str, port: int, session: aiohttp.ClientSession,
        collected: CollectedData
    ) -> tuple[Optional[str], dict]:
        try:
            url = f"https://{ip}:{port}"
            async with session.get(url, allow_redirects=True, max_redirects=3) as resp:
                headers = dict(resp.headers)
                html = None
                if resp.content_length and resp.content_length < 100000:
                    try:
                        html = await resp.text()
                    except Exception:
                        pass

                collected.raw_responses.append(RawResponse(
                    ip=ip, port=port, module="https", endpoint="/",
                    status_code=resp.status,
                    content_type=headers.get("Content-Type"),
                    raw_data=(html or "").encode(errors="replace")
                ))

                return html, headers
        except Exception:
            pass
        return None, {}

    async def _fetch_endpoints(
        self, ip: str, port: int, session: aiohttp.ClientSession,
        collected: CollectedData
    ) -> None:
        paths = [p for p in self._endpoint_paths if p != "/"]
        if not paths:
            return

        sem = asyncio.Semaphore(5)

        async def _fetch_one(path: str) -> None:
            async with sem:
                try:
                    url = f"https://{ip}:{port}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=self._timeout)) as resp:
                        if resp.status != 200:
                            return
                        content = await resp.text()
                        if not content:
                            return

                        content_type = (resp.headers.get("Content-Type") or "").lower()

                        collected.raw_responses.append(RawResponse(
                            ip=ip, port=port, module="https", endpoint=path,
                            status_code=resp.status,
                            content_type=resp.headers.get("Content-Type"),
                            raw_data=content.encode(errors="replace")
                        ))

                        if "xml" in content_type or content.strip().startswith("<?xml"):
                            collected.xml_texts.append(content)
                        elif "json" in content_type or (content.strip().startswith("{") and content.strip().endswith("}")):
                            collected.json_texts.append(content)
                        elif "<?xml" in content or "<methodResponse" in content:
                            collected.xml_texts.append(content)
                except Exception:
                    pass

        await asyncio.gather(*[_fetch_one(p) for p in paths])

    async def _extract_ssl_subject(self, ip: str, port: int, collected: CollectedData) -> None:
        """Extract SSL certificate subject for signature matching."""
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_context),
                timeout=self._timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            cert = ssl_object.getpeercert() if ssl_object else None
            writer.close()
            await writer.wait_closed()

            if cert:
                subject_parts = []
                for rdns in cert.get("subject", ()):
                    for attr, val in rdns:
                        subject_parts.append(f"{attr}={val}")
                if subject_parts:
                    collected.ssl_subject = ", ".join(subject_parts)
        except Exception:
            pass

    def supported_ports(self) -> Set[int]:
        return {443, 8443, 10443, 9443}

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
