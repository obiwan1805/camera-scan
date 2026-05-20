"""Core interfaces for all pipeline components."""
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Optional


class InputSource(ABC):
    """Base class for input sources."""

    @abstractmethod
    async def read(self) -> AsyncIterator[Any]:
        yield


class Scanner(ABC):
    """Base for any scanner implementation (Layer 1)."""

    @abstractmethod
    async def scan(self, input_source: InputSource) -> AsyncIterator[Any]:
        """Scan input and yield items."""
        yield


class Filter(ABC):
    """Base for any processing layer (Layer 2, 3, etc.)."""

    @abstractmethod
    async def process(self, item: Any) -> Optional[Any]:
        """Process an item, return None to drop it."""
        pass


class Writer(ABC):
    """Base for any storage backend."""

    @abstractmethod
    async def write(self, items: list[Any]) -> int:
        """Write items, return number written."""
        pass