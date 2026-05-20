"""Header parser for camera identification."""
import re
from typing import Optional, Dict, List


HEADER_PATTERNS: Dict[str, List[str]] = {
    "hikvision": [
        r"App/WebServer/\d+\.\d+",
        r"DVRDVS-Webs",
        r"HIKVISION",
        r"Hikvision",
        r"webserver",
        r"DVRDVS"
    ],
    "dahua": [
        r"DahuaWEB",
        r"DVR WEB CLIENT",
        r"Dahua",
        r"dahua",
        r"DVRDVS",
        r"DH-IPC",
        r"DH-NVR"
    ],
    "axis": [
        r"Axis",
        r"axis",
        r"AXIS",
        r"Communications"
    ],
    "foscam": [
        r"Foscam",
        r"foscam",
        r"FI89",
        r"FI98",
        r"FI99"
    ],
    "vivotek": [
        r"Vivotek",
        r"vivotek",
        r"VIVOTEK"
    ],
    "panasonic": [
        r"Panasonic",
        r"panasonic",
        r"WV-"
    ],
    "sony": [
        r"Sony",
        r"sony",
        r"SONY",
        r"SNC-"
    ],
    "mobotix": [
        r"Mobotix",
        r"mobotix",
        r"MOBOTIX"
    ],
    "ubiquiti": [
        r"Ubiquiti",
        r"ubiquiti",
        r"UniFi",
        r"airVision"
    ]
}


def detect_vendor_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """Detect vendor from HTTP headers."""
    server = headers.get("Server", "").lower()
    x_frame_options = headers.get("X-Frame-Options", "").lower()
    set_cookie = headers.get("Set-Cookie", "").lower()
    www_authenticate = headers.get("WWW-Authenticate", "").lower()

    header_text = " ".join([server, x_frame_options, set_cookie, www_authenticate])

    for vendor, patterns in HEADER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, header_text, re.IGNORECASE):
                return vendor

    return None


def extract_model_from_headers(headers: Dict[str, str], vendor: str) -> Optional[str]:
    """Extract model from HTTP headers based on vendor."""
    server = headers.get("Server", "")

    if vendor == "hikvision":
        # Hikvision sometimes includes model in Server header
        model_match = re.search(r"DS-2CD\d+[A-Za-z\d-]*", server)
        if model_match:
            return model_match.group(0)

    elif vendor == "dahua":
        # Dahua sometimes includes model in Server header
        model_match = re.search(r"IPC-HFW\d+[A-Za-z\d-]*", server)
        if model_match:
            return model_match.group(0)
        model_match = re.search(r"IPC-HDBW\d+[A-Za-z\d-]*", server)
        if model_match:
            return model_match.group(0)

    elif vendor == "axis":
        # Axis camera models
        model_match = re.search(r"Q\d+[A-Za-z\d-]*", server)
        if model_match:
            return model_match.group(0)

    return None


def get_vendor_ports(vendor: str) -> List[int]:
    """Get common ports for a vendor."""
    vendor_ports = {
        "hikvision": [80, 8080, 443, 554, 8000, 8443],
        "dahua": [80, 8080, 443, 554, 37777, 8000, 8443],
        "axis": [80, 8080, 443, 554],
        "foscam": [80, 8080, 443, 554],
        "vivotek": [80, 8080, 443, 554],
        "sony": [80, 8080, 443, 554],
        "panasonic": [80, 8080, 443, 554],
        "ubiquiti": [80, 8080, 443, 554, 7443],
    }
    return vendor_ports.get(vendor, [])