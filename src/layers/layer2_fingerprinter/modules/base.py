"""Base interface for protocol modules."""
from abc import ABC, abstractmethod
from typing import Set, Optional
from src.storage.schemas import Fingerprint


class ProtocolModule(ABC):
    @abstractmethod
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None) -> Optional[Fingerprint]:
        pass

    @abstractmethod
    def supported_ports(self) -> Set[int]:
        pass