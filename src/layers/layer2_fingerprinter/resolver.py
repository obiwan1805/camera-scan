"""Resolver -- aggregates match results into a single best Fingerprint."""
from typing import Dict, List, Optional
from pydantic import BaseModel
from src.storage.schemas import Fingerprint, EvidenceItem


class MatchResult(BaseModel):
    """A single match from the signature engine."""
    vendor: str
    field: str           # "vendor", "model", "version"
    value: str
    source: str          # "favicon_hash", "headers", "xml_text", etc.
    pattern: str
    cves: List[str] = []


class AggregationResolver:
    """Resolves all match results into a single best Fingerprint.

    - Vendor: majority vote (most matches wins)
    - Model: longest value among winning vendor's matches
    - Version: longest value among winning vendor's matches
    - CVEs: union of all CVEs from all winning matches
    """

    def resolve(self, matches: List[MatchResult]) -> Optional[Fingerprint]:
        if not matches:
            return None

        # Step 1: Determine vendor by vote count (only from field=vendor matches)
        vendor_counts: Dict[str, int] = {}
        vendor_total: Dict[str, int] = {}
        for m in matches:
            if m.field == "vendor" and not m.vendor.startswith("_"):
                vendor_counts[m.vendor] = vendor_counts.get(m.vendor, 0) + 1
            if not m.vendor.startswith("_"):
                vendor_total[m.vendor] = vendor_total.get(m.vendor, 0) + 1

        if not vendor_counts:
            return None

        def _sort_key(v):
            return (vendor_counts.get(v, 0), vendor_total.get(v, 0))

        best_vendor = max(vendor_counts, key=_sort_key)

        # Step 2: Collect all matches for the winning vendor
        vendor_matches = [m for m in matches if m.vendor == best_vendor]

        # Step 3: Pick model -- longest value (most specific)
        model_candidates = [m for m in vendor_matches if m.field == "model"]
        best_model = self._pick_longest(model_candidates)

        # Step 4: Pick version -- longest value
        version_candidates = [m for m in vendor_matches if m.field == "version"]
        best_version = self._pick_longest(version_candidates)

        # Step 5: Collect CVEs from all winning matches
        all_cves = set()
        for m in vendor_matches:
            all_cves.update(m.cves)

        # Step 6: Build evidence items
        evidence_items = [
            EvidenceItem(
                field=m.field,
                value=m.value,
                source=m.source,
                pattern=m.pattern,
                cves=m.cves,
            )
            for m in vendor_matches
        ]

        # Step 7: Infer services from sources
        services = list(set(m.source for m in vendor_matches))

        return Fingerprint(
            vendor=best_vendor,
            model=best_model,
            version=best_version,
            services=services,
            probe_method=", ".join(sorted(set(m.source for m in vendor_matches))),
            evidence_items=evidence_items,
            cves=sorted(all_cves),
        )

    def _pick_longest(self, candidates: List[MatchResult]) -> Optional[str]:
        if not candidates:
            return None
        # Prefer longest value as most specific
        return max(candidates, key=lambda m: len(m.value)).value
