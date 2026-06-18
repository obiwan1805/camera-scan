"""Base class for all probers."""
from abc import ABC, abstractmethod
from typing import Optional, Set
from .types import CollectedData


class Prober(ABC):
    """Base class for protocol-specific data collectors.

    Probers fetch raw data and merge it into CollectedData.
    They contain zero signature matching logic.
    """

    protocol: Optional[str] = None

    @abstractmethod
    async def probe(self, ip: str, port: int, collected: CollectedData) -> CollectedData:
        """Probe target and merge results into collected data."""
        pass

    @abstractmethod
    def supported_ports(self) -> Set[int]:
        pass

    async def close(self) -> None:
        """Clean up resources (sessions, connections). Override if needed."""
        pass
