"""Authentication checker orchestrator — dispatches to banner or MSF detector."""
import asyncio
from typing import List
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo, CameraFingerprint
from src.utils.logging import setup_logger
from .protocol_map import get_protocol, is_web_protocol
from .banner_detector import BannerDetector
from .msf_detector import MSFDetector


class AuthChecker:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._banner = BannerDetector(config)
        self._msf = MSFDetector(config, msf_client)
        self._logger = setup_logger("AuthChecker")

    async def check(self, item: CameraFingerprint) -> List[AuthInfo]:
        if not self._config.enabled:
            return []

        ip = item.ip
        port = item.port
        protocol = get_protocol(port)

        if is_web_protocol(protocol):
            result = await self._msf.detect(ip, port, protocol)
            return [result]

        result = await self._banner.detect(ip, port, protocol)

        if protocol == "unknown" and not result.has_login:
            raw = result.raw_response.lower()
            if "http/" in raw or "<html" in raw:
                web_result = await self._msf.detect(ip, port, "http")
                return [web_result]

        return [result]
