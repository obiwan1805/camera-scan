"""Protocol modules."""
from .base import ProtocolModule
from .favicon import FaviconModule
from .https import HTTPSModule
from .http import HTTPModule
from .rtsp import RTSPModule
from .onvif import ONVIFModule

MODULE_REGISTRY = {
    "favicon": FaviconModule,
    "https": HTTPSModule,
    "http": HTTPModule,
    "rtsp": RTSPModule,
    "onvif": ONVIFModule,
}

__all__ = [
    "ProtocolModule",
    "FaviconModule",
    "HTTPSModule",
    "HTTPModule",
    "RTSPModule",
    "ONVIFModule",
    "MODULE_REGISTRY"
]