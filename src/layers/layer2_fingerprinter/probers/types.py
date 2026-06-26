"""Data types for the prober layer."""
from typing import Dict, List, Optional
from pydantic import BaseModel
from src.storage.schemas import RawResponse


class CollectedData(BaseModel):
    """All raw data collected from a single target, ready for signature matching."""
    ip: str
    port: int

    html: Optional[str] = None
    headers: Dict[str, str] = {}
    xml_texts: List[str] = []
    json_texts: List[str] = []
    rtsp_banner: Optional[str] = None
    onvif_response: Optional[str] = None
    favicon_hash: Optional[int] = None
    ssl_subject: Optional[str] = None
    html_hash: Optional[int] = None
    dom_hash: Optional[int] = None
    title_hash: Optional[int] = None

    raw_responses: List[RawResponse] = []
    protocols: List[str] = []

    class Config:
        arbitrary_types_allowed = True
