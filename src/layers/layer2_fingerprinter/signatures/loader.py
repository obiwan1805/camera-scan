import yaml
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from .schema import (
    BrandKeyword,
    SignaturePattern,
    EndpointProbe,
    OnvifParser,
    ExtraPattern,
    VendorSignature,
)


class SignatureLoader:
    def __init__(self, signatures_dir: str = "config/signatures"):
        self._dir = Path(signatures_dir)
        self._signatures: Dict[str, VendorSignature] = {}
        self.load_all()

    def load_all(self) -> None:
        """Load or reload all YAML files from disk."""
        self._signatures.clear()
        for yaml_file in sorted(self._dir.glob("*.yaml")):
            if yaml_file.name.startswith("__"):
                continue
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            sig = VendorSignature(**data)
            self._signatures[sig.vendor] = sig

    def reload(self) -> Tuple[int, int]:
        """Reload from disk. Returns (before_count, after_count)."""
        before = len(self._signatures)
        self.load_all()
        return before, len(self._signatures)

    @property
    def signatures(self) -> List[VendorSignature]:
        return list(self._signatures.values())

    def get_vendor(self, vendor: str) -> Optional[VendorSignature]:
        return self._signatures.get(vendor)

    def get_all_endpoints(self) -> List[Tuple[str, EndpointProbe]]:
        """Returns (vendor_name, EndpointProbe) for all endpoints across all signatures."""
        result = []
        for sig in self.signatures:
            for ep in sig.endpoint_probes:
                result.append((sig.vendor, ep))
        return result

    def get_unique_endpoint_paths(self) -> set[str]:
        """All unique endpoint paths across all signatures."""
        paths = set()
        for sig in self.signatures:
            for ep in sig.endpoint_probes:
                paths.add(ep.path)
        return paths

    def get_all_rtsp_paths(self) -> List[str]:
        """All RTSP paths across all signatures, deduplicated."""
        paths = []
        seen = set()
        for sig in self.signatures:
            for p in sig.rtsp_paths:
                if p not in seen:
                    paths.append(p)
                    seen.add(p)
        return paths

    def add_pattern(self, vendor: str, pattern_type: str, pattern_data: dict) -> None:
        """Add a pattern to a vendor's signature and persist to YAML."""
        sig = self._signatures.get(vendor)
        if not sig:
            # Create new vendor
            sig = VendorSignature(vendor=vendor)
            self._signatures[vendor] = sig

        # Add to appropriate list
        if pattern_type == "favicon_hash":
            sig.favicon_hashes.append(pattern_data["hash"])
        elif pattern_type == "brand_keyword":
            sig.brand_keywords.append(BrandKeyword(**pattern_data))
        elif pattern_type == "model":
            sig.model_patterns.append(SignaturePattern(**pattern_data))
        elif pattern_type == "version":
            sig.version_patterns.append(SignaturePattern(**pattern_data))
        elif pattern_type == "endpoint":
            sig.endpoint_probes.append(EndpointProbe(**pattern_data))
        elif pattern_type == "onvif":
            sig.onvif_parsers.append(OnvifParser(**pattern_data))
        elif pattern_type == "rtsp_path":
            sig.rtsp_paths.append(pattern_data["path"])
        elif pattern_type == "extra":
            sig.extra_patterns.append(ExtraPattern(**pattern_data))

        self._save_vendor(vendor)

    def remove_pattern(self, vendor: str, pattern_type: str, index: int) -> bool:
        """Remove a pattern by type and index. Returns True if found."""
        sig = self._signatures.get(vendor)
        if not sig:
            return False

        type_to_list = {
            "favicon_hash": sig.favicon_hashes,
            "brand_keyword": sig.brand_keywords,
            "model": sig.model_patterns,
            "version": sig.version_patterns,
            "endpoint": sig.endpoint_probes,
            "onvif": sig.onvif_parsers,
            "rtsp_path": sig.rtsp_paths,
            "extra": sig.extra_patterns,
        }

        lst = type_to_list.get(pattern_type)
        if lst is None or index < 0 or index >= len(lst):
            return False

        lst.pop(index)
        self._save_vendor(vendor)
        return True

    def _save_vendor(self, vendor: str) -> None:
        """Persist a vendor's signature to YAML file."""
        sig = self._signatures.get(vendor)
        if not sig:
            return
        filepath = self._dir / f"{vendor}.yaml"
        data = sig.model_dump(exclude_defaults=True)
        # Ensure vendor and aliases always present
        data["vendor"] = sig.vendor
        if "aliases" not in data:
            data["aliases"] = []
        with open(filepath, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
