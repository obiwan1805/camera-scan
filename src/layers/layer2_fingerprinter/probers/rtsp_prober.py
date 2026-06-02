"""RTSP prober -- collects DESCRIBE/OPTIONS banner data."""
import asyncio
from typing import Optional, Set, List
from .base import Prober
from .types import CollectedData
from src.storage.schemas import RawResponse

# Default generic RTSP paths
_DEFAULT_RTSP_PATHS = ["/stream1", "/live", "/h264", "/"]


class RTSPProber(Prober):
    """Collects RTSP banner data from DESCRIBE and OPTIONS requests."""

    def __init__(self, extra_paths: Optional[List[str]] = None):
        self._paths = list(_DEFAULT_RTSP_PATHS)
        if extra_paths:
            seen = set(self._paths)
            for p in extra_paths:
                if p not in seen:
                    self._paths.append(p)
                    seen.add(p)

    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        for path in self._paths:
            result = await self._rtsp_describe(ip, port, path, collected)
            if result:
                break

        if not collected.rtsp_banner:
            await self._rtsp_options(ip, port, collected)

        return collected

    async def _rtsp_describe(
        self, ip: str, port: int, path: str, collected: CollectedData
    ) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )

            request = (
                f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: RTSP Client\r\n"
                f"\r\n"
            )
            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(2048), timeout=3)
            writer.close()
            await writer.wait_closed()

            collected.raw_responses.append(RawResponse(
                ip=ip, port=port, module="rtsp", endpoint=path,
                raw_data=response
            ))

            response_str = response.decode(errors="ignore")
            if response_str.startswith("RTSP/"):
                collected.rtsp_banner = response_str
                return True

        except Exception:
            pass
        return False

    async def _rtsp_options(self, ip: str, port: int, collected: CollectedData) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )

            request = (
                f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: RTSP Client\r\n"
                f"\r\n"
            )
            writer.write(request.encode())
            await writer.drain()

            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            collected.raw_responses.append(RawResponse(
                ip=ip, port=port, module="rtsp", endpoint="/",
                raw_data=response
            ))

            response_str = response.decode(errors="ignore")
            if response_str.startswith("RTSP/"):
                if not collected.rtsp_banner:
                    collected.rtsp_banner = response_str

        except Exception:
            pass

    def supported_ports(self) -> Set[int]:
        return {554, 8554, 10554}
