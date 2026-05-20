"""Data models using Pydantic for validation."""
from datetime import datetime
from typing import Optional, List
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