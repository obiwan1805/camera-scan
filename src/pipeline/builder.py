"""Pipeline builder for constructing the processing graph."""
from typing import List
from src.core.config import Config
from src.core.queue_protocol import QueueProtocol, InMemoryQueue, BoundedQueue
from src.storage.base import StorageBackend
from src.storage.sqlite_backend import SQLiteBackend


class PipelineBuilder:
    """Builds the pipeline based on configuration."""

    def __init__(self, config: Config):
        self.config = config

    def build_queues(self) -> List[QueueProtocol]:
        queues = []
        for i in range(2):
            base_queue = InMemoryQueue(maxsize=0)
            queue = BoundedQueue(base_queue, self.config.queue.maxsize)
            queues.append(queue)
        return queues

    def build_storage(self) -> StorageBackend:
        if self.config.storage.backend == "sqlite":
            return SQLiteBackend(self.config.storage.path)
        raise ValueError(f"Unknown storage backend: {self.config.storage.backend}")

    def get_layer2_modules(self) -> List[str]:
        return self.config.layer2.modules


class Pipeline:
    """Orchestrates the pipeline layers."""

    def __init__(
        self,
        layers: List,
        queues: List[QueueProtocol],
        storage: StorageBackend,
        input_source=None
    ):
        self.layers = layers
        self.queues = queues
        self.storage = storage
        self.input_source = input_source
        self._running = False

    async def start(self) -> None:
        self._running = True
        await self.storage.connect()
        for i, layer in enumerate(self.layers):
            if hasattr(layer, "start"):
                if i == 0 and self.input_source:
                    await layer.start(self.input_source)
                else:
                    await layer.start()

    async def stop(self) -> None:
        self._running = False
        for layer in self.layers:
            if hasattr(layer, "stop"):
                await layer.stop()
        for queue in self.queues:
            queue.close()
        await self.storage.disconnect()

    def is_running(self) -> bool:
        return self._running