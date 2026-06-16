"""Port-to-protocol mapping for authentication detection."""

KNOWN_PROTOCOLS = {
    22: "ssh",
    2222: "ssh",
    23: "telnet",
    21: "ftp",
    554: "rtsp",
    8554: "rtsp",
    80: "http",
    8080: "http",
    8000: "http",
    8888: "http",
    443: "https",
    8443: "https",
}

WEB_PROTOCOLS = {"http", "https"}


def get_protocol(port: int) -> str:
    return KNOWN_PROTOCOLS.get(port, "unknown")


def is_web_protocol(protocol: str) -> bool:
    return protocol in WEB_PROTOCOLS
