"""High confidence strategy — NVD search for targets with model + version."""
from typing import Optional
from src.storage.schemas import CameraFingerprint, PoC
from src.utils.logging import setup_logger
from .base import SearchStrategy


class HighConfidenceStrategy(SearchStrategy):
    """NVD search for weight==1.0 targets (vendor + model + version known)."""

    def __init__(self):
        self._logger = setup_logger("HighConfidenceStrategy")

    async def execute(self, item, nvd_client, msf_client, storage) -> Optional[CameraFingerprint]:
        fp = item.fingerprint
        vendor = fp.vendor
        model = fp.model
        version = fp.version

        # 1. NVD search — cached by (vendor, model, version)
        cve_entries = await nvd_client.search(vendor, model, version)
        if not cve_entries:
            return item

        cve_ids = []
        for entry in cve_entries:
            cve_ids.append(entry.cve_id)

            # 2. Check if MSF has module for this CVE
            msf_module = msf_client.find_module_for_cve(vendor, entry.cve_id) if msf_client else None

            # 3. Create PoC entry
            poc = PoC(
                name=f"{entry.cve_id}_{vendor}",
                cve_id=entry.cve_id,
                vendor=vendor,
                target_names=[model] if model else [],
                severity=entry.severity,
                description=entry.description,
                script_type=msf_module.get("type") if msf_module else None,
                script_content=msf_module.get("name") if msf_module else None,
            )
            await storage.submit("pocs", [poc])

        # 4. Fill cves
        fp.cves = list(set(cve_ids))
        self._logger.info(
            f"[HIGH] {item.ip}:{item.port} — {vendor} {model} {version} — {len(fp.cves)} CVEs"
        )
        return item
