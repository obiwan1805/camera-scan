"""NVD API client with rate limiting and caching."""
import asyncio
from typing import Dict, List, Optional
import aiohttp
from src.core.config import NVDConfig
from src.storage.schemas import CVEEntry
from src.layers.layer3_cve_searcher.cache import NVDResultCache
from src.utils.logging import setup_logger


class NVDClient:
    """NVD CVE API 2.0 client with token bucket rate limiter."""

    def __init__(self, config: NVDConfig):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache = NVDResultCache()
        self._enrich_cache: Dict[str, dict] = {}
        self._logger = setup_logger("NVDClient")

        # Token bucket rate limiter
        self._tokens = config.rate_limit
        self._max_tokens = config.rate_limit
        self._last_refill = 0.0
        self._refill_interval = 30.0
        self._lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _acquire_rate_limit(self) -> None:
        """Token bucket rate limiter — blocks until a token is available."""
        async with self._lock:
            now = asyncio.get_running_loop().time()
            elapsed = now - self._last_refill
            if elapsed >= self._refill_interval:
                self._tokens = self._max_tokens
                self._last_refill = now
            if self._tokens <= 0:
                wait = self._refill_interval - elapsed
                self._logger.info(f"Rate limit reached, waiting {wait:.1f}s")
                await asyncio.sleep(wait)
                self._tokens = self._max_tokens
                self._last_refill = asyncio.get_running_loop().time()
            self._tokens -= 1

    def _build_search_params(self, vendor: str, model: str, version: Optional[str]) -> dict:
        keyword = f"{vendor} {model}"
        params = {"keywordSearch": keyword}
        if self.config.api_key:
            params["apiKey"] = self.config.api_key
        return params

    def _parse_response(self, data: dict) -> List[CVEEntry]:
        """Parse NVD API 2.0 response into CVEEntry list."""
        entries = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS
            severity = None
            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                    break

            entries.append(CVEEntry(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=description,
                source="nvd",
            ))
        return entries

    async def search(self, vendor: str, model: str, version: Optional[str]) -> List[CVEEntry]:
        """Search NVD for CVEs. Returns cached results if available."""
        if version:
            cached = self._cache.get(vendor, model, version)
            if cached is not None:
                self._logger.info(f"NVD cache hit: {vendor} {model} {version}")
                return cached

        params = self._build_search_params(vendor, model, version)

        for attempt in range(3):
            try:
                await self._acquire_rate_limit()
                session = await self._get_session()
                async with session.get(self.config.base_url, params=params) as resp:
                    if resp.status == 403:
                        self._logger.warning("NVD rate limit (403), backing off")
                        await asyncio.sleep(30 * (attempt + 1))
                        continue
                    if resp.status == 503:
                        self._logger.warning(f"NVD unavailable (503), attempt {attempt+1}")
                        await asyncio.sleep(10 * (attempt + 1))
                        continue
                    if resp.status != 200:
                        self._logger.error(f"NVD error: {resp.status}")
                        return []
                    data = await resp.json()
                    entries = self._parse_response(data)
                    if version:
                        self._cache.put(vendor, model, version, entries)
                    return entries
            except Exception as e:
                self._logger.error(f"NVD request failed: {e}")
                if attempt == 2:
                    return []
                await asyncio.sleep(5 * (attempt + 1))
        return []

    async def enrich(self, cve_ids: List[str]) -> List[dict]:
        """Enrich CVE IDs with metadata (severity, CVSS, description)."""
        results = []
        for cve_id in cve_ids:
            if cve_id in self._enrich_cache:
                results.append(self._enrich_cache[cve_id])
                continue
            params = {"cveId": cve_id}
            if self.config.api_key:
                params["apiKey"] = self.config.api_key
            try:
                await self._acquire_rate_limit()
                session = await self._get_session()
                async with session.get(self.config.base_url, params=params) as resp:
                    if resp.status != 200:
                        results.append({"cve_id": cve_id})
                        continue
                    data = await resp.json()
                    entries = self._parse_response(data)
                    if entries:
                        meta = {
                            "cve_id": cve_id,
                            "severity": entries[0].severity,
                            "cvss_score": entries[0].cvss_score,
                            "description": entries[0].description,
                        }
                        self._enrich_cache[cve_id] = meta
                        results.append(meta)
                    else:
                        results.append({"cve_id": cve_id})
            except Exception as e:
                self._logger.error(f"NVD enrich failed for {cve_id}: {e}")
                results.append({"cve_id": cve_id})
        return results

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
