"""TCP banner grabbing for authentication detection on known protocols."""
import asyncio
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512


class BannerDetector:
    def __init__(self, config: AuthCheckConfig):
        self._timeout = config.banner_timeout
        self._logger = setup_logger("BannerDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        try:
            if protocol == "ssh":
                return await self._detect_ssh(ip, port)
            elif protocol == "telnet":
                return await self._detect_telnet(ip, port)
            elif protocol == "rtsp":
                return await self._detect_rtsp(ip, port)
            elif protocol == "ftp":
                return await self._detect_ftp(ip, port)
            else:
                return await self._detect_unknown(ip, port)
        except (ConnectionRefusedError, ConnectionResetError, OSError, asyncio.TimeoutError):
            return AuthInfo(port=port, protocol=protocol, has_login=False, auth_type="unknown")

    async def _detect_ssh(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            banner = data.decode(errors="replace")
            has_login = "SSH-" in banner
            return AuthInfo(
                port=port, protocol="ssh", has_login=has_login,
                auth_type="password" if has_login else "unknown",
                raw_response=banner[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_telnet(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            text = data.decode(errors="replace").lower()
            has_login = any(kw in text for kw in ["login:", "username:", "password:"])
            return AuthInfo(
                port=port, protocol="telnet", has_login=has_login,
                auth_type="password" if has_login else "unknown",
                raw_response=data.decode(errors="replace")[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_rtsp(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            request = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=self._timeout)
            text = data.decode(errors="replace")
            has_login = "401" in text
            auth_type = "unknown"
            if has_login:
                text_lower = text.lower()
                if "digest" in text_lower:
                    auth_type = "digest"
                elif "basic" in text_lower:
                    auth_type = "basic"
            return AuthInfo(
                port=port, protocol="rtsp", has_login=has_login,
                auth_type=auth_type,
                raw_response=text[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_ftp(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            welcome = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            welcome_text = welcome.decode(errors="replace")
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            response_text = response.decode(errors="replace")
            code = response_text[:3]
            if code == "331":
                auth_type = "password"
            elif code == "230":
                auth_type = "anonymous"
            else:
                return AuthInfo(
                    port=port, protocol="ftp", has_login=False, auth_type="unknown",
                    raw_response=(welcome_text + response_text)[:MAX_RAW_RESPONSE],
                )
            return AuthInfo(
                port=port, protocol="ftp", has_login=True,
                auth_type=auth_type,
                raw_response=(welcome_text + response_text)[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_unknown(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            except asyncio.TimeoutError:
                return AuthInfo(port=port, protocol="unknown", has_login=False, auth_type="unknown")
            text = data.decode(errors="replace")
            text_lower = text.lower()
            if "SSH-" in text:
                return AuthInfo(
                    port=port, protocol="ssh", has_login=True,
                    auth_type="password", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if any(kw in text_lower for kw in ["login:", "username:", "password:"]):
                return AuthInfo(
                    port=port, protocol="telnet", has_login=True,
                    auth_type="password", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if "RTSP/" in text:
                has_login = "401" in text
                return AuthInfo(
                    port=port, protocol="rtsp", has_login=has_login,
                    auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if text.startswith("220"):
                return AuthInfo(
                    port=port, protocol="ftp", has_login=True,
                    auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
                )
            return AuthInfo(
                port=port, protocol="unknown", has_login=False,
                auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()
