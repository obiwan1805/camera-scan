"""Signature engine -- runs ALL signatures against collected data."""
import re
from typing import List, Optional
from .signatures.schema import VendorSignature
from .probers.types import CollectedData
from .resolver import MatchResult
from src.utils.logging import setup_logger


class SignatureEngine:
    """Runs all loaded vendor signatures against collected data.
    Returns every match found -- does not stop at first match.
    """

    def __init__(self, signatures: List[VendorSignature]):
        self.signatures = signatures
        self._logger = setup_logger("SignatureEngine")

    def match(self, data: CollectedData) -> List[MatchResult]:
        """Run ALL signatures against collected data. Return every match."""
        results: List[MatchResult] = []
        for sig in self.signatures:
            results.extend(self._match_vendor(sig, data))
        return results

    def _match_vendor(self, sig: VendorSignature, data: CollectedData) -> List[MatchResult]:
        results: List[MatchResult] = []

        # 1. Favicon hash
        if data.favicon_hash is not None:
            for h in sig.favicon_hashes:
                if data.favicon_hash == h:
                    results.append(MatchResult(
                        vendor=sig.vendor, field="vendor",
                        value=sig.vendor, source="favicon_hash",
                        pattern=str(h), cves=[]
                    ))

        # 2. Brand keywords
        for kw in sig.brand_keywords:
            text = self._get_scoped_text(kw.scope, data)
            if text and re.search(kw.pattern, text, re.IGNORECASE):
                results.append(MatchResult(
                    vendor=sig.vendor, field="vendor",
                    value=sig.vendor, source=kw.scope[0] if kw.scope else "unknown",
                    pattern=kw.pattern, cves=kw.cves
                ))

        # 3. Model patterns
        for mp in sig.model_patterns:
            text = self._get_scoped_text(mp.scope, data)
            if text:
                flags = re.DOTALL
                if not mp.case_sensitive:
                    flags |= re.IGNORECASE
                m = re.search(mp.regex, text, flags)
                if m:
                    value = m.group(mp.group).strip() if mp.group else m.group(0).strip()
                    if value:
                        results.append(MatchResult(
                            vendor=sig.vendor, field="model",
                            value=value, source=mp.scope[0] if mp.scope else "unknown",
                            pattern=mp.regex, cves=mp.cves
                        ))

        # 4. Version patterns
        for vp in sig.version_patterns:
            text = self._get_scoped_text(vp.scope, data)
            if text:
                flags = re.DOTALL
                if not vp.case_sensitive:
                    flags |= re.IGNORECASE
                m = re.search(vp.regex, text, flags)
                if m:
                    value = m.group(vp.group).strip() if vp.group else m.group(0).strip()
                    if value:
                        value = self._normalize(value, vp.normalize)
                        # Skip XML declaration versions
                        if value not in ("V1.0", "V1.1", "1.0", "1.1"):
                            results.append(MatchResult(
                                vendor=sig.vendor, field="version",
                                value=value, source=vp.scope[0] if vp.scope else "unknown",
                                pattern=vp.regex, cves=vp.cves
                            ))

        # 5. ONVIF parsers
        for onvif in sig.onvif_parsers:
            if data.onvif_response:
                # Check manufacturer match
                manufacturer_match = False
                for alias in onvif.manufacturer_match:
                    pattern = rf'<(?:\w+:)?Manufacturer>([^<]*)</(?:\w+:)?Manufacturer>'
                    m = re.search(pattern, data.onvif_response, re.IGNORECASE)
                    if m and alias.lower() in m.group(1).lower():
                        manufacturer_match = True
                        results.append(MatchResult(
                            vendor=sig.vendor, field="vendor",
                            value=sig.vendor, source="onvif_response",
                            pattern=f"Manufacturer={m.group(1)}", cves=[]
                        ))
                        break

                if manufacturer_match:
                    # Extract model
                    model_pattern = rf'<(?:\w+:)?{onvif.model_tag.split(":")[-1]}>([^<]*)</(?:\w+:)?{onvif.model_tag.split(":")[-1]}>'
                    m = re.search(model_pattern, data.onvif_response, re.IGNORECASE)
                    if m and m.group(1).strip():
                        results.append(MatchResult(
                            vendor=sig.vendor, field="model",
                            value=m.group(1).strip(), source="onvif_response",
                            pattern=onvif.model_tag, cves=[]
                        ))

                    # Extract firmware
                    fw_pattern = rf'<(?:\w+:)?{onvif.firmware_tag.split(":")[-1]}>([^<]*)</(?:\w+:)?{onvif.firmware_tag.split(":")[-1]}>'
                    m = re.search(fw_pattern, data.onvif_response, re.IGNORECASE)
                    if m and m.group(1).strip():
                        results.append(MatchResult(
                            vendor=sig.vendor, field="version",
                            value=m.group(1).strip(), source="onvif_response",
                            pattern=onvif.firmware_tag, cves=[]
                        ))

        # 6. Extra patterns -- dispatch by type
        for ep in sig.extra_patterns:
            if ep.type == "ssl_cn":
                if data.ssl_subject and ep.regex:
                    if re.search(ep.regex, data.ssl_subject, re.IGNORECASE):
                        results.append(MatchResult(
                            vendor=sig.vendor, field="vendor",
                            value=sig.vendor, source="ssl_cert",
                            pattern=ep.regex, cves=ep.cves
                        ))
            # Unknown types are silently skipped

        return results

    def _get_scoped_text(self, scopes: List[str], data: CollectedData) -> Optional[str]:
        """Concatenate all data buckets matching the requested scopes."""
        parts = []
        for scope in scopes:
            if scope == "html" and data.html:
                parts.append(data.html)
            elif scope == "headers":
                parts.append(" ".join(f"{k}: {v}" for k, v in data.headers.items()))
            elif scope == "xml_text":
                parts.extend(data.xml_texts)
            elif scope == "json_text":
                parts.extend(data.json_texts)
            elif scope == "rtsp_banner" and data.rtsp_banner:
                parts.append(data.rtsp_banner)
            elif scope == "onvif_response" and data.onvif_response:
                parts.append(data.onvif_response)
        return " ".join(parts) if parts else None

    def _normalize(self, value: str, method: Optional[str]) -> str:
        if method == "prefix_v":
            if not value.upper().startswith("V"):
                value = f"V{value}"
        elif method == "clean_v":
            value = re.sub(r'[^vV\d.]', '', value)
            if value and not value.upper().startswith("V"):
                value = f"V{value}"
        elif method == "uppercase":
            value = value.upper()
        return value
