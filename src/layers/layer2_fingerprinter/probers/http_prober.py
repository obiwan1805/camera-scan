"""HTTP prober -- collects HTML, headers, and endpoint responses."""
import asyncio
from typing import Optional, Set
import aiohttp
from .base import Prober
from .types import CollectedData
from src.storage.schemas import RawResponse
from src.utils.logging import setup_logger


class HTTPProber(Prober):
    """Collects data via HTTP: main page, headers, and all signature endpoint probes."""

    def __init__(self, endpoint_paths: Optional[set[str]] = None):
        self._endpoint_paths = endpoint_paths or set()
        self._logger = setup_logger("HTTPProber")
        self._session: Optional[aiohttp.ClientSession] = None

    def set_endpoints(self, paths: set[str]) -> None:
        self._endpoint_paths = paths

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            )
        return self._session

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        try:
            session = await self._get_session()
            html, headers = await self._fetch_root(ip, port, session, collected)
            if html:
                collected.html = html
            if headers:
                collected.headers.update(headers)

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
            url = f"http://{ip}:{port}"
            async with session.get(url, allow_redirects=True, max_redirects=3) as resp:
                headers = dict(resp.headers)
                html = None
                if resp.content_length and resp.content_length < 100000:
                    try:
                        html = await resp.text()
                    except Exception:
                        pass

                collected.raw_responses.append(RawResponse(
                    ip=ip, port=port, module="http", endpoint="/",
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
                    url = f"http://{ip}:{port}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status != 200:
                            return
                        content = await resp.text()
                        if not content:
                            return

                        content_type = (resp.headers.get("Content-Type") or "").lower()

                        collected.raw_responses.append(RawResponse(
                            ip=ip, port=port, module="http", endpoint=path,
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
                        elif content.strip().startswith("{") and content.strip().endswith("}"):
                            collected.json_texts.append(content)
                        elif "=" in content and "\n" in content:
                            collected.xml_texts.append(content)
                except Exception:
                    pass

        await asyncio.gather(*[_fetch_one(p) for p in paths])

    def supported_ports(self) -> Set[int]:
        return {80, 8080, 8000, 8001, 8081, 8086, 8090, 8200, 8888, 9000}

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
