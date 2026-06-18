"""Data models using Pydantic for validation."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Optional, List
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """A single match from the signature engine."""
    field: str           # "vendor", "model", "version"
    value: str
    source: str          # "favicon_hash", "headers", "xml_text", etc.
    pattern: str
    cves: List[str] = []


class PortScanResult(BaseModel):
    """Result from Layer 1 (Port Scanner)."""
    ip: str
    port: int
    status: str = "open"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Fingerprint(BaseModel):
    """Fingerprint information from Layer 2."""
    vendor: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[str] = None
    services: List[str] = []
    probe_method: Optional[str] = None
    endpoint: Optional[str] = None
    evidence_items: List[EvidenceItem] = []
    cves: List[str] = []

    @property
    def evidence(self) -> Optional[str]:
        return "; ".join(
            f"{e.field}={e.value} via {e.source}"
            for e in self.evidence_items
        ) or None

    @property
    def matched_pattern(self) -> Optional[str]:
        return "; ".join(e.pattern for e in self.evidence_items) or None


class CVEEntry(BaseModel):
    """Internal model for in-memory CVE processing — not stored directly."""
    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    msf_module: Optional[str] = None
    exploitable: bool = False
    source: str = ""       # "nvd" | "msf_check" | "nvd+msf_check"
    verified: bool = False


class CameraFingerprint(BaseModel):
    """Complete fingerprint result from Layer 2."""
    ip: str
    port: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "fingerprint_done"
    fingerprint: Fingerprint
    weight: float = 0.0
    protocol: Optional[str] = None


class RawResponse(BaseModel):
    """Raw response from a Layer 2 probe."""
    ip: str
    port: int
    module: str
    endpoint: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    raw_data: bytes

    MAX_SIZE: ClassVar[int] = 1_048_576  # 1 MB

    def truncated_data(self) -> bytes:
        return self.raw_data[:self.MAX_SIZE]


@dataclass
class ProbeResult:
    """Return type for module probe() -- fingerprint + collected raw responses."""
    fingerprint: Optional[Fingerprint] = None
    raw_responses: List[RawResponse] = field(default_factory=list)


class PoC(BaseModel):
    name: str
    cve_id: Optional[str] = None
    vendor: Optional[str] = None
    target_names: List[str] = []
    protocol: Optional[str] = None
    script_type: Optional[str] = None
    script_content: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: bool = True


class DictEntry(BaseModel):
    dict_type: str
    value: str


class ScanTarget(BaseModel):
    target: str
    type: str = "cidr"
