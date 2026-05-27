"""Storage interface and base classes."""
from abc import ABC, abstractmethod
from typing import Any, List, Optional


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

    # Queue operations for durable queue support

    @abstractmethod
    async def enqueue_item(self, queue_name: str, item_key: str, item_data: str) -> None:
        pass

    @abstractmethod
    async def claim_item(self, queue_name: str, item_key: str) -> None:
        pass

    @abstractmethod
    async def ack_item(self, queue_name: str, item_key: str) -> None:
        pass

    @abstractmethod
    async def fail_item(self, queue_name: str, item_key: str) -> None:
        pass

    @abstractmethod
    async def recover_queue(self, queue_name: str, source_collection: str, sink_collection: Optional[str]) -> List[tuple]:
        pass

    @abstractmethod
    async def has_fingerprint(self, ip: str, port: int) -> bool:
        pass