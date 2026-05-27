"""Pipeline builder for constructing the processing graph."""
from typing import List
from src.core.config import Config
from src.core.queue_protocol import QueueProtocol
from src.core.durable_queue import DurableQueue
from src.storage.base import StorageBackend
from src.storage.sqlite_backend import SQLiteBackend
from src.utils.logging import setup_logger


class PipelineBuilder:
    """Builds the pipeline based on configuration."""

    def __init__(self, config: Config):
        self.config = config
        self._logger = setup_logger("PipelineBuilder")

    def build_queues(self, storage: StorageBackend) -> List[QueueProtocol]:
        queue_configs = [
            ("queue_0", "port_scans", "fingerprints"),
            ("queue_1", "fingerprints", None),
        ]
        queues = []
        for name, source, sink in queue_configs:
            queues.append(DurableQueue(storage, name, source, sink))
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

        # Recover queue state from DB before starting layers
        for queue in self.queues:
            if isinstance(queue, DurableQueue):
                recovered = await queue.recover()
                if recovered > 0:
                    setup_logger("Pipeline").info(f"Recovered {recovered} items for {queue._queue_name}")

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