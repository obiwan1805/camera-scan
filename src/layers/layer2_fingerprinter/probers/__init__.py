"""Probers -- protocol-specific data collectors."""
from .base import Prober
from .types import CollectedData
from .http_prober import HTTPProber
from .https_prober import HTTPSProber
from .rtsp_prober import RTSPProber
from .onvif_prober import ONVIFProber
from .favicon_prober import FaviconProber

PROBER_REGISTRY = {
    "http": HTTPProber,
    "https": HTTPSProber,
    "rtsp": RTSPProber,
    "onvif": ONVIFProber,
    "favicon": FaviconProber,
}

__all__ = [
    "Prober",
    "CollectedData",
    "HTTPProber",
    "HTTPSProber",
    "RTSPProber",
    "ONVIFProber",
    "FaviconProber",
    "PROBER_REGISTRY",
]
