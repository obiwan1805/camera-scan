"""Protocol modules."""
from .base import ProtocolModule
from .favicon import FaviconModule
from .https import HTTPSModule
from .http import HTTPModule
from .rtsp import RTSPModule
from .onvif import ONVIFModule
from .ssh import SSHModule

MODULE_REGISTRY = {
    "favicon": FaviconModule,
    "https": HTTPSModule,
    "http": HTTPModule,
    "rtsp": RTSPModule,
    "onvif": ONVIFModule,
    "ssh": SSHModule
}

__all__ = [
    "ProtocolModule",
    "FaviconModule",
    "HTTPSModule",
    "HTTPModule",
    "RTSPModule",
    "ONVIFModule",
    "SSHModule",
    "MODULE_REGISTRY"
]