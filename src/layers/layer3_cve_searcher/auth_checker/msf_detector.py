"""MSF auxiliary scanner + HTTP form heuristic for web auth detection."""
import asyncio
import re
from typing import Optional
import aiohttp
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512

LOGIN_PATHS = ["/", "/login", "/login.html", "/admin", "/cgi-bin/login"]
PASSWORD_INPUT = re.compile(r'<input[^>]*type=["\']?password', re.IGNORECASE)


class MSFDetector:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._msf_client = msf_client
        self._logger = setup_logger("MSFDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        scheme = "https" if protocol == "https" else "http"

        try:
            tasks = []
            if self._msf_client:
                tasks.append(self._detect_msf_http(ip, port))
            tasks.append(self._detect_form_login(ip, port, scheme))
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, AuthInfo) and r.has_login:
                    return r
        except Exception as e:
            self._logger.warning(f"Auth detection failed for {ip}:{port}: {e}")

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
        except Exception as e:
            self._logger.warning(f"MSF http_login failed for {ip}:{port}: {e}")
            return AuthInfo(port=port, protocol="http", has_login=False, auth_type="unknown")
        finally:
            if console_id is not None:
                try:
                    await self._msf_client._call("console.destroy", str(console_id))
                except Exception:
                    pass

    async def _detect_form_login(self, ip: str, port: int, scheme: str) -> Optional[AuthInfo]:
        try:
            timeout = aiohttp.ClientTimeout(total=self._config.banner_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for path in LOGIN_PATHS:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        async with session.get(url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 401:
                                auth_header = resp.headers.get("WWW-Authenticate", "")
                                auth_type = "basic" if "basic" in auth_header.lower() else (
                                    "digest" if "digest" in auth_header.lower() else "unknown"
                                )
                                return AuthInfo(
                                    port=port, protocol=scheme, has_login=True,
                                    auth_type=auth_type,
                                    raw_response=f"HTTP 401 at {path}"[:MAX_RAW_RESPONSE],
                                )
                            html = await resp.text(errors="replace")
                            if PASSWORD_INPUT.search(html):
                                return AuthInfo(
                                    port=port, protocol=scheme, has_login=True,
                                    auth_type="form",
                                    raw_response=f"Password input found at {path}"[:MAX_RAW_RESPONSE],
                                )
                    except Exception:
                        continue
        except Exception as e:
            self._logger.debug(f"Form detection failed for {ip}:{port}: {e}")
        return None
