"""Layer 3: CVE Searcher (placeholder)."""
from typing import Optional
from src.core.interfaces import Filter
from src.storage.schemas import CameraFingerprint


class CVESearcher(Filter):
    async def process(self, item: CameraFingerprint) -> Optional[dict]:
        if item.weight >= 0.8:
            return {"cves": [], "method": "cpe_database"}
        elif item.weight >= 0.5:
            return {"cves": [], "method": "hybrid"}
        else:
            return {"cves": [], "method": "llm_reasoning"}


__all__ = ["CVESearcher"]