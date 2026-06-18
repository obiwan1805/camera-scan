"""MSF auxiliary scanner for HTTP auth detection (401/Basic/Digest)."""
import asyncio
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512


class MSFDetector:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._msf_client = msf_client
        self._logger = setup_logger("MSFDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        if not self._msf_client:
            return AuthInfo(
                port=port, protocol=protocol, has_login=False, auth_type="unknown",
            )
        try:
            return await self._detect_msf_http(ip, port)
        except Exception as e:
            self._logger.warning(f"MSF http_login failed for {ip}:{port}: {e}")
            return AuthInfo(
                port=port, protocol=protocol, has_login=False, auth_type="unknown",
            )

    async def _detect_msf_http(self, ip: str, port: int) -> AuthInfo:
        console_id = None
        try:
            resp = await self._msf_client._call("console.create")
            console_id = self._msf_client._val(resp, "id")
            if isinstance(console_id, bytes):
                console_id = console_id.decode()

            cmd = (
                f"use auxiliary/scanner/http/http_login\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
                f"set STOP_ON_SUCCESS false\n"
                f"set BLANK_PASSWORDS false\n"
                f"set VERBOSE true\n"
                f"run\n"
            )
            await self._msf_client._call("console.write", str(console_id), cmd)

            output = ""
            elapsed = 0
            interval = 2
            timeout = self._config.msf_detect_timeout

            while elapsed < timeout:
                await asyncio.sleep(interval)
                elapsed += interval
                resp = await self._msf_client._call("console.read", str(console_id))
                chunk = self._msf_client._val(resp, "data") or b""
                if isinstance(chunk, bytes):
                    chunk = chunk.decode(errors="replace")
                output += chunk
                busy = self._msf_client._val(resp, "busy")
                if not busy and elapsed >= interval * 2:
                    break

            auth_type = "unknown"
            has_login = False
            output_lower = output.lower()
            if "401" in output or "www-authenticate" in output_lower:
                has_login = True
                if "basic" in output_lower:
                    auth_type = "basic"
                elif "digest" in output_lower:
                    auth_type = "digest"

            return AuthInfo(
                port=port, protocol="http", has_login=has_login,
                auth_type=auth_type,
                raw_response=output[:MAX_RAW_RESPONSE],
                msf_module="auxiliary/scanner/http/http_login",
            )
        finally:
            if console_id is not None:
                try:
                    await self._msf_client._call("console.destroy", str(console_id))
                except Exception:
                    pass
