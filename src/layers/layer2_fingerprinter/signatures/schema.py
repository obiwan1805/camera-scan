from typing import List, Optional, Literal

from pydantic import BaseModel


class BrandKeyword(BaseModel):
    pattern: str
    scope: List[str]  # "html", "headers", "xml_text", "json_text", "rtsp_banner", "onvif_response", "ssl_cert"
    cves: List[str] = []


class SignaturePattern(BaseModel):
    regex: str
    scope: List[str]
    group: int = 0
    normalize: Optional[str] = None  # "prefix_v", "clean_v", "uppercase"
    case_sensitive: bool = False
    cves: List[str] = []


class EndpointProbe(BaseModel):
    path: str
    protocol: List[str]  # "http", "https"
    content_type: Optional[str] = None  # "xml", "json", "html", "text", "binary"


class OnvifParser(BaseModel):
    manufacturer_match: List[str]
    model_tag: str = "tds:Model"
    firmware_tag: str = "tds:FirmwareVersion"


class ExtraPattern(BaseModel):
    type: str
    regex: Optional[str] = None
    scope: List[str] = []
    attribute: Optional[str] = None  # for html_attribute type
    cves: List[str] = []


class VendorSignature(BaseModel):
    vendor: str
    aliases: List[str] = []
    favicon_hashes: List[int] = []
    brand_keywords: List[BrandKeyword] = []
    model_patterns: List[SignaturePattern] = []
    version_patterns: List[SignaturePattern] = []
    endpoint_probes: List[EndpointProbe] = []
    onvif_parsers: List[OnvifParser] = []
    rtsp_paths: List[str] = []
    extra_patterns: List[ExtraPattern] = []
