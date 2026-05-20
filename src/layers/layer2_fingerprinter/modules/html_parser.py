"""HTML parser for camera identification."""
import re
from typing import Optional, Dict, List


TITLE_PATTERNS: Dict[str, List[str]] = {
    "hikvision": [
        r"Network Video Recorder",
        r"Digital Video Recorder",
        r"DS-2CD\d+[A-Za-z\d-]*",
        r"DS-2TD\d+[A-Za-z\d-]*",
        r"DS-2DE\d+[A-Za-z\d-]*",
        r"DS-2PT\d+[A-Za-z\d-]*",
        r"DS-2CF\d+[A-Za-z\d-]*",
        r"DS-2EF\d+[A-Za-z\d-]*",
        r"iVMS-\d+",
        r"Hikvision"
    ],
    "dahua": [
        r"IPC-HFW\d+[A-Za-z\d-]*",
        r"IPC-HDBW\d+[A-Za-z\d-]*",
        r"IPC-HDW\d+[A-Za-z\d-]*",
        r"IPC-HDB\d+[A-Za-z\d-]*",
        r"SD\d+[A-Za-z\d-]*",
        r"HCVR\d+[A-Za-z\d-]*",
        r"NVR\d+[A-Za-z\d-]*",
        r"Dahua",
        r"DMSS"
    ],
    "axis": [
        r"AXIS \d+[A-Za-z\d-]*",
        r"Q\d+[A-Za-z\d-]*",
        r"P\d+[A-Za-z\d-]*",
        r"M\d+[A-Za-z\d-]*",
        r"Axis"
    ],
    "foscam": [
        r"FI89\d+[A-Za-z\d-]*",
        r"FI98\d+[A-Za-z\d-]*",
        r"FI99\d+[A-Za-z\d-]*",
        r"Foscam"
    ],
    "vivotek": [
        r"FD\d+[A-Za-z\d-]*",
        r"IP\d+[A-Za-z\d-]*",
        r"FE\d+[A-Za-z\d-]*",
        r"IB\d+[A-Za-z\d-]*",
        r"Vivotek"
    ],
    "sony": [
        r"SNC-\w+",
        r"Sony",
        r"SONY"
    ],
    "panasonic": [
        r"WV-\w+",
        r"KX-\w+",
        r"Panasonic",
        r"BB-\w+"
    ],
    "mobotix": [
        r"M\d+[A-Za-z\d-]*",
        r"Mobotix"
    ],
    "ubiquiti": [
        r"UniFi",
        r"airVision",
        r"airCam"
    ]
}


def detect_vendor_from_html(html: str) -> Optional[str]:
    """Detect vendor from HTML content."""
    if not html:
        return None

    html_lower = html.lower()

    # Check for vendor-specific keywords in the entire HTML
    vendor_keywords = {
        "hikvision": ["hikvision", "ivms", "hik-connect"],
        "dahua": ["dahua", "dmss", "smartpss"],
        "axis": ["axis", "axis communications"],
        "foscam": ["foscam"],
        "vivotek": ["vivotek"],
        "sony": ["sony", "snc-"],
        "panasonic": ["panasonic", "wv-", "bb-"],
        "mobotix": ["mobotix", "m24", "m12", "mxegg"],
        "ubiquiti": ["ubiquiti", "unifi", "airvision", "aircam"]
    }

    for vendor, keywords in vendor_keywords.items():
        for keyword in keywords:
            if keyword in html_lower:
                return vendor

    return None


def extract_model_from_html(html: str, vendor: str) -> Optional[str]:
    """Extract model from HTML content based on vendor."""
    if not html:
        return None

    # Extract title tag
    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1) if title_match else ""

    # Also check meta description and keywords
    desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    description = desc_match.group(1) if desc_match else ""

    # Check all text content
    text_content = " ".join([title, description, html])

    if vendor in TITLE_PATTERNS:
        for pattern in TITLE_PATTERNS[vendor]:
            model_match = re.search(pattern, text_content, re.IGNORECASE)
            if model_match:
                return model_match.group(0)

    return None


def extract_version_from_html(html: str) -> Optional[str]:
    """Extract version from HTML content."""
    if not html:
        return None

    # Look for version patterns
    version_patterns = [
        r"V\d+\.\d+\.\d+\.\d+",
        r"v\d+\.\d+\.\d+",
        r"Firmware[\s:]+([vV]?\d+\.\d+)",
        r"Version[\s:]+([vV]?\d+\.\d+)",
        r"FW[\s:]+([vV]?\d+\.\d+)",
    ]

    for pattern in version_patterns:
        match = re.search(pattern, html)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            return version.upper() if version.startswith("V") else f"V{version}"

    return None


def parse_login_page_title(html: str) -> Optional[str]:
    """Extract information from camera login page title."""
    if not html:
        return None

    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        # Clean up common prefixes/suffixes
        title = re.sub(r'\s*-\s*.*', '', title)  # Remove everything after dash
        title = re.sub(r'\s*\|\s*.*', '', title)  # Remove everything after pipe
        return title

    return None