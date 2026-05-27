"""SSH fingerprint module."""
import asyncio
from typing import Optional, Set
from src.layers.layer2_fingerprinter.modules.base import ProtocolModule
from src.storage.schemas import Fingerprint, ProbeResult, RawResponse


class SSHModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[ProbeResult]:
        raw_responses = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )
            banner = await reader.read(512)
            writer.close()
            await writer.wait_closed()

            raw_responses.append(RawResponse(
                ip=ip, port=port, module="ssh", endpoint="/",
                raw_data=banner
            ))

            banner_str = banner.decode(errors="ignore")
            if "ssh" in banner_str.lower():
                vendor, matched_pattern, evidence = self._detect_vendor(banner_str)
                return ProbeResult(
                    fingerprint=Fingerprint(
                        vendor=vendor or "ssh_device",
                        raw_banner=banner_str[:256],
                        services=["ssh"],
                        probe_method="ssh_banner",
                        evidence=evidence,
                        matched_pattern=matched_pattern
                    ),
                    raw_responses=raw_responses
                )
        except Exception:
            pass

        if raw_responses:
            return ProbeResult(fingerprint=None, raw_responses=raw_responses)
        return None

    def supported_ports(self) -> Set[int]:
        return {22}

    def _detect_vendor(self, banner: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Detect vendor from SSH banner. Returns (vendor, pattern, evidence)."""
        patterns = {
            "hikvision": ("hikvision", "SSH banner contains 'hikvision'"),
            "dahua": ("dahua", "SSH banner contains 'dahua'"),
            "dropbear": ("embedded", "SSH banner contains 'dropbear' (embedded device)"),
            "openssh": ("openssh", "SSH banner contains 'OpenSSH'"),
            "busybox": ("embedded", "SSH banner contains 'busybox' (embedded device)"),
        }

        for vendor, (pattern, evidence) in patterns.items():
            if pattern in banner.lower():
                return vendor, pattern, evidence
        return None, None, "SSH protocol detected (vendor unknown)"
