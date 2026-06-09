"""In-memory caches for NVD results and MSF module info."""
from typing import Dict, List, Optional
from src.storage.schemas import CVEEntry


class NVDResultCache:
    """Cache NVD search results keyed by (vendor, model, version)."""

    def __init__(self):
        self._cache: Dict[tuple, List[CVEEntry]] = {}

    def get(self, vendor: str, model: str, version: str) -> Optional[List[CVEEntry]]:
        key = (vendor.lower(), model.lower(), version.lower())
        return self._cache.get(key)

    def put(self, vendor: str, model: str, version: str, entries: List[CVEEntry]) -> None:
        key = (vendor.lower(), model.lower(), version.lower())
        self._cache[key] = entries

    def size(self) -> int:
        return len(self._cache)


class MSFModuleCache:
    """Cache MSF module search results keyed by vendor."""

    def __init__(self):
        self._cache: Dict[str, List[dict]] = {}

    def get(self, vendor: str) -> Optional[List[dict]]:
        return self._cache.get(vendor.lower())

    def put(self, vendor: str, modules: List[dict]) -> None:
        self._cache[vendor.lower()] = modules

    def find_module_for_cve(self, vendor: str, cve_id: str) -> Optional[dict]:
        modules = self.get(vendor)
        if not modules:
            return None
        for m in modules:
            if cve_id in m.get("cves", []):
                return m
        return None

    def size(self) -> int:
        return len(self._cache)
