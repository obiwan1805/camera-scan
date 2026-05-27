"""Data models using Pydantic for validation."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Optional, List
from pydantic import BaseModel, Field


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
    # New fields for evidence
    probe_method: Optional[str] = None  # e.g., "http_server_header", "xml_endpoint", "rtsp_describe"
    evidence: Optional[str] = None      # e.g., "matched Server header: DVRDVS-Webs"
    matched_pattern: Optional[str] = None  # The regex or pattern that matched
    endpoint: Optional[str] = None      # e.g., "/ISAPI/System/deviceInfo"


class CameraFingerprint(BaseModel):
    """Complete fingerprint result from Layer 2."""
    ip: str
    port: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "fingerprint_done"
    fingerprint: Fingerprint
    weight: float = 0.0


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
    """Return type for module probe() — fingerprint + collected raw responses."""
    fingerprint: Optional[Fingerprint] = None
    raw_responses: List[RawResponse] = field(default_factory=list)