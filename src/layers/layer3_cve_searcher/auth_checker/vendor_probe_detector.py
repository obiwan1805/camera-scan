"""Vendor-specific and generic auth endpoint probing + SPA heuristics."""
import json
import re
from typing import Optional, List, Dict
import aiohttp
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512

VENDOR_PROBE_MAP: Dict[str, List[str]] = {
    "dahua": ["/cgi-bin/login.cgi"],
    "hikvision": ["/ISAPI/Security/userCheck", "/ISAPI/Security/sessionLogin/capabilities"],
    "axis": ["/axis-cgi/usergroup.cgi", "/axis-cgi/param.cgi"],
    "panasonic": ["/cgi-bin/login.cgi"],
    "ubiquiti": ["/api/auth/login"],
    "vivotek": ["/cgi-bin/admin/getparam.cgi"],
    "foscam": ["/cgi-bin/CGIProxy.fcgi?cmd=logIn"],
    "sony": ["/command/inquiry.cgi"],
    "mobotix": ["/control/userimage.html"],
}

GENERIC_PROBE_PATHS: List[str] = [
    "/cgi-bin/login.cgi",
    "/ISAPI/Security/userCheck",
    "/api/login",
    "/api/auth",
    "/cgi-bin/viewer/login.cgi",
    "/login.htm",
    "/login.php",
    "/admin/login.html",
]

LOGIN_TITLE_PATTERNS = [
    re.compile(r"\blogin\b", re.IGNORECASE),
    re.compile(r"^WEB SERVICE$", re.IGNORECASE),
    re.compile(r"^AXIS$", re.IGNORECASE),
    re.compile(r"\b(?:NVR|DVR|IPC)\b"),
    re.compile(r"\bUniFi\b", re.IGNORECASE),
]

SPA_FRAMEWORK_PATTERNS = [
    re.compile(r"Ext\.onReady|ext-all\.js", re.IGNORECASE),
    re.compile(r"SmartGWT|\.nocache\.js", re.IGNORECASE),
    re.compile(r"require\.js.*jsCore|jsCore.*require\.js", re.IGNORECASE | re.DOTALL),
]

CRYPTO_LOGIN_PATTERN = re.compile(r"md5\.js", re.IGNORECASE)
CRYPTO_RSA_PATTERN = re.compile(r"rsa\.js", re.IGNORECASE)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class VendorProbeDetector:
    def __init__(self, config: AuthCheckConfig):
        self._config = config
        self._logger = setup_logger("VendorProbeDetector")

    async def detect(
        self, ip: str, port: int, protocol: str, vendor: Optional[str],
    ) -> AuthInfo:
        scheme = "https" if protocol == "https" else "http"
        default = AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )

        try:
            timeout = aiohttp.ClientTimeout(total=self._config.banner_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # 1. Vendor-specific probes
                if vendor and vendor.lower() in VENDOR_PROBE_MAP:
                    paths = VENDOR_PROBE_MAP[vendor.lower()]
                    result = await self._probe_endpoints(
                        session, ip, port, scheme, protocol, paths,
                    )
                    if result:
                        return result

                # 2. Generic probes
                result = await self._probe_endpoints(
                    session, ip, port, scheme, protocol, GENERIC_PROBE_PATHS,
                )
                if result:
                    return result

                # 3. Heuristic: title + SPA framework
                result = await self._check_heuristics(
                    session, ip, port, scheme, protocol,
                )
                if result:
                    return result

        except Exception as e:
            self._logger.debug(f"VendorProbe failed for {ip}:{port}: {e}")

        return default

    async def _probe_endpoints(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        port: int,
        scheme: str,
        protocol: str,
        paths: List[str],
    ) -> Optional[AuthInfo]:
        for path in paths:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    if resp.status == 401:
                        auth_header = resp.headers.get("WWW-Authenticate", "")
                        auth_type = self._parse_auth_type(auth_header)
                        return AuthInfo(
                            port=port,
                            protocol=protocol,
                            has_login=True,
                            auth_type=auth_type,
                            raw_response=f"HTTP 401 at {path}"[:MAX_RAW_RESPONSE],
                            login_url=url,
                            confidence="high",
                            detection_method="vendor_probe",
                        )

                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        api_result = self._check_api_response(
                            body, url, port, protocol,
                        )
                        if api_result:
                            return api_result

            except Exception:
                continue
        return None

    def _check_api_response(
        self, body: str, url: str, port: int, protocol: str,
    ) -> Optional[AuthInfo]:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                keys_lower = {k.lower() for k in data.keys()}
                if keys_lower & {"error", "msg", "message", "result"}:
                    return AuthInfo(
                        port=port,
                        protocol=protocol,
                        has_login=True,
                        auth_type="api",
                        raw_response=body[:MAX_RAW_RESPONSE],
                        login_url=url,
                        confidence="high",
                        detection_method="vendor_probe",
                    )
        except (json.JSONDecodeError, ValueError):
            pass

        if re.search(r"<(?:result|CGI_Result)\b[^>]*>[^<]*</(?:result|CGI_Result)>", body, re.IGNORECASE):
            return AuthInfo(
                port=port,
                protocol=protocol,
                has_login=True,
                auth_type="api",
                raw_response=body[:MAX_RAW_RESPONSE],
                login_url=url,
                confidence="high",
                detection_method="vendor_probe",
            )

        return None

    async def _check_heuristics(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        port: int,
        scheme: str,
        protocol: str,
    ) -> Optional[AuthInfo]:
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                html = await resp.text(errors="replace")
        except Exception:
            return None

        title = self._extract_title(html)
        has_login_title = any(p.search(title) for p in LOGIN_TITLE_PATTERNS) if title else False
        has_spa = any(p.search(html) for p in SPA_FRAMEWORK_PATTERNS)
        has_crypto = bool(CRYPTO_LOGIN_PATTERN.search(html) and CRYPTO_RSA_PATTERN.search(html))

        if has_login_title and (has_spa or has_crypto):
            return AuthInfo(
                port=port,
                protocol=protocol,
                has_login=True,
                auth_type="spa_login",
                raw_response=f"Heuristic: title={title!r}"[:MAX_RAW_RESPONSE],
                login_url=url,
                confidence="low",
                detection_method="heuristic",
            )

        return None

    def _extract_title(self, html: str) -> Optional[str]:
        match = TITLE_RE.search(html)
        if match:
            return match.group(1).strip()
        return None

    def _parse_auth_type(self, header: str) -> str:
        h = header.lower()
        if "digest" in h:
            return "digest"
        if "basic" in h:
            return "basic"
        return "unknown"
