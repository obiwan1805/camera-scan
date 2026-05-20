"""Queue abstraction with multiple implementations."""
from abc import ABC, abstractmethod
from asyncio import Queue
from multiprocessing import Queue as MPQueue
from typing import Any, Optional
import asyncio


class QueueProtocol(ABC):
    """Queue interface for layer communication."""

    @abstractmethod
    async def put(self, item: Any, timeout: Optional[float] = None) -> None:
        pass

    @abstractmethod
    async def get(self, timeout: Optional[float] = None) -> Any:
        pass

    @abstractmethod
    def is_full(self) -> bool:
        pass

    @abstractmethod
    def size(self) -> int:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class InMemoryQueue(QueueProtocol):
    """Asyncio in-memory queue for testing."""

    def __init__(self, maxsize: int = 0):
        self._queue: Queue = Queue(maxsize=maxsize)

    async def put(self, item: Any, timeout: Optional[float] = None) -> None:
        await asyncio.wait_for(self._queue.put(item), timeout)

    async def get(self, timeout: Optional[float] = None) -> Any:
        return await asyncio.wait_for(self._queue.get(), timeout)

    def is_full(self) -> bool:
        return self._queue.full()

    def size(self) -> int:
        return self._queue.qsize()

    def close(self) -> None:
        pass


class MultiprocessingQueueAdapter(QueueProtocol):
    """Adapter for multiprocessing.Queue."""

    def __init__(self, maxsize: int = 0):
        self._queue: MPQueue = MPQueue(maxsize=maxsize)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        return self._loop

    async def put(self, item: Any, timeout: Optional[float] = None) -> None:
        loop = self._ensure_loop()
        await loop.run_in_executor(None, lambda: self._queue.put(item, timeout=timeout or -1))

    async def get(self, timeout: Optional[float] = None) -> Any:
        loop = self._ensure_loop()
        return await loop.run_in_executor(None, lambda: self._queue.get(timeout=timeout or -1))

    def is_full(self) -> bool:
        return self._queue.full()

    def size(self) -> int:
        return self._queue.qsize()

    def close(self) -> None:
        self._queue.close()


class BoundedQueue(QueueProtocol):
    """Bounded queue with backpressure."""

    def __init__(self, queue: QueueProtocol, maxsize: int, backpressure: str = "block"):
        self._queue = queue
        self._maxsize = maxsize
        self._backpressure = backpressure

    async def put(self, item: Any, timeout: Optional[float] = None) -> None:
        if self._backpressure == "block" and self.is_full():
            await self._queue.put(item, timeout)
        elif self._backpressure == "drop" and self.is_full():
            return
        else:
            await self._queue.put(item, timeout)

    async def get(self, timeout: Optional[float] = None) -> Any:
        return await self._queue.get(timeout)

    def is_full(self) -> bool:
        return self._queue.size() >= self._maxsize

    def size(self) -> int:
        return self._queue.size()

    def close(self) -> None:
        self._queue.close()