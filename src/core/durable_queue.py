"""Durable queue backed by DB claims table with in-memory async delivery."""
import asyncio
import json
from typing import Any, Optional
from .queue_protocol import QueueProtocol
from ..storage.base import StorageBackend
from ..storage.schemas import CameraFingerprint


class DurableQueue(QueueProtocol):
    """Hybrid queue: in-memory for speed, DB claims for durability and crash recovery."""

    def __init__(
        self,
        storage: StorageBackend,
        queue_name: str,
        source_collection: str,
        sink_collection: Optional[str] = None,
    ):
        self._storage = storage
        self._queue_name = queue_name
        self._source = source_collection
        self._sink = sink_collection
        self._mem_queue: asyncio.Queue = asyncio.Queue()
        self._logger_msg_shown = False

    async def recover(self) -> int:
        """Restore queue state from DB. Returns number of recovered items."""
        items = await self._storage.recover_queue(
            self._queue_name, self._source, self._sink
        )
        for item in items:
            if isinstance(item, tuple):
                await self._mem_queue.put(item)
            elif isinstance(item, CameraFingerprint):
                await self._mem_queue.put(item)
        return len(items)

    async def put(self, item: Any, timeout: Optional[float] = None) -> None:
        item_key = self._make_key(item)
        item_data = self._serialize(item)
        await self._storage.enqueue_item(self._queue_name, item_key, item_data)
        await asyncio.wait_for(self._mem_queue.put(item), timeout)

    async def get(self, timeout: Optional[float] = None) -> Any:
        item = await asyncio.wait_for(self._mem_queue.get(), timeout)
        item_key = self._make_key(item)
        await self._storage.claim_item(self._queue_name, item_key)
        return item

    async def ack(self, item: Any) -> None:
        item_key = self._make_key(item)
        await self._storage.ack_item(self._queue_name, item_key)

    async def mark_failed(self, item: Any) -> None:
        item_key = self._make_key(item)
        await self._storage.fail_item(self._queue_name, item_key)

    def size(self) -> int:
        return self._mem_queue.qsize()

    def is_full(self) -> bool:
        return False

    def close(self) -> None:
        pass

    def _make_key(self, item: Any) -> str:
        if isinstance(item, tuple) and len(item) == 2:
            return f"{item[0]}:{item[1]}"
        if isinstance(item, CameraFingerprint):
            return f"{item.ip}:{item.port}"
        return str(item)

    def _serialize(self, item: Any) -> str:
        if isinstance(item, tuple) and len(item) == 2:
            return json.dumps({"ip": item[0], "port": item[1]})
        if isinstance(item, CameraFingerprint):
            return item.model_dump_json()
        return json.dumps(item)
