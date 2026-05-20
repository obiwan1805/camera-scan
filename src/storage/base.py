"""Storage interface and base classes."""
from abc import ABC, abstractmethod
from typing import Any, List


class StorageBackend(ABC):
    """Base interface for storage backends."""

    @abstractmethod
    async def connect(self) -> None:
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        pass

    @abstractmethod
    async def write(self, collection: str, items: List[Any]) -> int:
        pass

    @abstractmethod
    async def read(self, collection: str, query: dict) -> List[Any]:
        pass

    @abstractmethod
    async def count(self, collection: str) -> int:
        pass