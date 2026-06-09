"""Output classification — exploitability status and impact types.

Computed at display time from existing data. No new storage fields.
"""
from typing import List
from src.storage.schemas import Fingerprint, PoC


def classify_exploitability(fingerprint: Fingerprint, pocs: List[PoC]) -> str:
    """Classify target exploitability based on CVE results and PoC availability.

    Returns: "exploitable" | "affected" | "unclear" | "no_result"
    """
    if not fingerprint.cves:
        return "no_result"

    has_poc = any(
        poc.script_content
        for poc in pocs
        if poc.cve_id in fingerprint.cves
    )

    if has_poc:
        return "exploitable"

    if fingerprint.version:
        return "affected"

    return "unclear"


def classify_impact(
    cve_description: str,
    cwe: str,
    msf_module_type: str,
    msf_module_name: str,
) -> List[str]:
    """Classify CVE impact type from description, CWE, and MSF module info.

    Returns list of impact tags: "rce", "auth_bypass", "video_access",
    "info_leak", "dos", or ["unknown"] if none match.
    """
    desc = (cve_description or "").lower()
    impacts = []

    # RCE
    if cwe in ("CWE-78", "CWE-94", "CWE-119") or "command injection" in desc:
        impacts.append("rce")

    # Auth bypass
    if cwe == "CWE-287" or any(kw in desc for kw in [
        "auth bypass", "default credential", "password bypass",
        "authentication bypass", "bypass authentication",
    ]):
        impacts.append("auth_bypass")

    # Video access
    if any(kw in desc for kw in ["stream", "video", "rtsp", "camera feed"]):
        impacts.append("video_access")

    # Info leak
    if cwe == "CWE-200" or any(kw in desc for kw in [
        "information disclosure", "information exposure",
        "credentials", "sensitive", "snapshot",
    ]):
        impacts.append("info_leak")

    # DoS
    if cwe == "CWE-400" or any(kw in desc for kw in [
        "denial of service", "crash", "reboot",
    ]):
        impacts.append("dos")

    return impacts or ["unknown"]


# Display helpers for Discord bot
STATUS_EMOJI = {
    "exploitable": "🔴",
    "affected": "🟠",
    "unclear": "🟡",
    "no_result": "⚪",
}

IMPACT_LABELS = {
    "rce": "RCE",
    "auth_bypass": "Auth bypass",
    "video_access": "Video access",
    "info_leak": "Info leak",
    "dos": "DoS",
    "unknown": "Unknown",
}
