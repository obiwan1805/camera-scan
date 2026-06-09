"""Low confidence strategy — MSF check for targets without full identification."""
import asyncio
from typing import Optional, List
from src.storage.schemas import CameraFingerprint, PoC
from src.utils.logging import setup_logger
from .base import SearchStrategy


class LowConfidenceStrategy(SearchStrategy):
    """MSF check for weight<1.0 targets (vendor known, model/version partial)."""

    def __init__(self, module_semaphore: asyncio.Semaphore):
        self._module_semaphore = module_semaphore
        self._logger = setup_logger("LowConfidenceStrategy")

    async def execute(self, item, nvd_client, msf_client, storage) -> Optional[CameraFingerprint]:
        fp = item.fingerprint
        vendor = fp.vendor

        # 1. Search MSF modules — cached by vendor
        try:
            modules = await msf_client.search_modules(vendor)
        except Exception as e:
            self._logger.warning(f"MSF search failed for {vendor}: {e} — falling back to NVD only")
            if nvd_client:
                cve_entries = await nvd_client.search(vendor, fp.model or "", fp.version)
                for entry in cve_entries:
                    fp.cves.append(entry.cve_id)
                    poc = PoC(
                        name=f"{entry.cve_id}_{vendor}",
                        cve_id=entry.cve_id,
                        vendor=vendor,
                        target_names=[fp.model] if fp.model else [],
                        severity=entry.severity,
                        description=entry.description,
                    )
                    await storage.submit("pocs", [poc])
                fp.cves = list(set(fp.cves))
            return item

        if not modules:
            return item

        # 2. Check each module
        confirmed_cves = []
        for module in modules:
            async with self._module_semaphore:
                try:
                    result = await msf_client.check(module["name"], item.ip, item.port)
                    if result.get("status") == "vulnerable":
                        confirmed_cves.extend(module.get("cves", []))
                        poc = PoC(
                            name=f"{module['name']}_{item.ip}_{item.port}",
                            cve_id=module["cves"][0] if module.get("cves") else None,
                            vendor=vendor,
                            target_names=[fp.model] if fp.model else [],
                            script_type=module.get("type"),
                            script_content=module.get("name"),
                        )
                        await storage.submit("pocs", [poc])
                except Exception as e:
                    self._logger.error(f"MSF check error for {module['name']} on {item.ip}: {e}")

        # 3. NVD enrich confirmed CVEs
        if confirmed_cves and nvd_client:
            unique_cves = list(set(confirmed_cves))
            enriched = await nvd_client.enrich(unique_cves)
            for meta in enriched:
                poc = PoC(
                    name=f"{meta['cve_id']}_{vendor}",
                    cve_id=meta["cve_id"],
                    vendor=vendor,
                    severity=meta.get("severity"),
                    description=meta.get("description"),
                    target_names=[fp.model] if fp.model else [],
                )
                await storage.submit("pocs", [poc])

        # 4. Fill cves
        fp.cves = list(set(confirmed_cves))
        self._logger.info(
            f"[LOW] {item.ip}:{item.port} — {vendor} — {len(fp.cves)} confirmed CVEs"
        )
        return item
