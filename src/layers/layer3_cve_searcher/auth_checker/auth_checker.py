"""Authentication checker orchestrator — dispatches to banner, MSF, form, or vendor probe detector."""
import asyncio
from typing import List, Optional
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo, CameraFingerprint
from src.utils.logging import setup_logger
from .protocol_map import get_protocol, is_web_protocol
from .banner_detector import BannerDetector
from .msf_detector import MSFDetector
from .form_detector import FormDetector
from .vendor_probe_detector import VendorProbeDetector


class AuthChecker:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._banner = BannerDetector(config)
        self._msf = MSFDetector(config, msf_client)
        self._form = FormDetector(config)
        self._vendor_probe = VendorProbeDetector(config)
        self._semaphore = asyncio.Semaphore(config.max_auth_concurrency)
        self._logger = setup_logger("AuthChecker")

    async def check(self, item: CameraFingerprint) -> List[AuthInfo]:
        if not self._config.enabled:
            return []

        async with self._semaphore:
            return await self._check_inner(item)

    async def _check_inner(self, item: CameraFingerprint) -> List[AuthInfo]:
        ip = item.ip
        port = item.port
        protocol = get_protocol(port)
        vendor = item.fingerprint.vendor

        if is_web_protocol(protocol):
            result = await self._check_web(ip, port, protocol, vendor)
            return [result]

        result = await self._banner.detect(ip, port, protocol)

        if protocol == "unknown" and not result.has_login:
            raw = result.raw_response.lower()
            if "http/" in raw or "<html" in raw:
                web_result = await self._check_web(ip, port, "http", vendor)
                return [web_result]

        return [result]

    async def _check_web(
        self, ip: str, port: int, protocol: str, vendor: Optional[str],
    ) -> AuthInfo:
        msf_result, form_result, vendor_result = await asyncio.gather(
            self._msf.detect(ip, port, protocol),
            self._form.detect(ip, port, protocol),
            self._vendor_probe.detect(ip, port, protocol, vendor),
            return_exceptions=True,
        )

        if isinstance(form_result, Exception):
            self._logger.debug(f"FormDetector error for {ip}:{port}: {form_result}")
            form_result = None
        if isinstance(msf_result, Exception):
            self._logger.debug(f"MSFDetector error for {ip}:{port}: {msf_result}")
            msf_result = None
        if isinstance(vendor_result, Exception):
            self._logger.debug(f"VendorProbe error for {ip}:{port}: {vendor_result}")
            vendor_result = None

        if form_result and form_result.has_login:
            return form_result
        if vendor_result and vendor_result.has_login and vendor_result.confidence == "high":
            return vendor_result
        if msf_result and msf_result.has_login:
            return msf_result
        if vendor_result and vendor_result.has_login and vendor_result.confidence == "low":
            return vendor_result
        return AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )
