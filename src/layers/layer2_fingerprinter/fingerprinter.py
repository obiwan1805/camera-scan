"""Main fingerprinter implementing Filter interface with semaphore-based processing."""
import asyncio
from typing import Optional
from src.core.interfaces import Filter
from src.core.queue_protocol import QueueProtocol
from src.storage.base import StorageBackend
from src.storage.schemas import CameraFingerprint, Fingerprint
from src.core.config import Layer2Config
from src.layers.layer2_fingerprinter.modules import MODULE_REGISTRY
from src.utils.logging import setup_logger


class Fingerprinter(Filter):
    def __init__(
        self,
        config: Layer2Config,
        input_queue: QueueProtocol,
        output_queue: QueueProtocol,
        storage: StorageBackend
    ):
        self.config = config
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.storage = storage
        self.logger = setup_logger("Fingerprinter")
        self.modules = [MODULE_REGISTRY[name]() for name in config.modules]
        self._max_concurrent = config.worker_pool.max_concurrent or 200
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._status_task: Optional[asyncio.Task] = None

        # Progress counters
        self._processed = 0
        self._successful = 0
        self._failed = 0
        self._start_time = None
        self._processing_count = 0

    async def start(self) -> None:
        self._running = True
        self._start_time = asyncio.get_event_loop().time()
        self._task = asyncio.create_task(self._run())
        self._status_task = asyncio.create_task(self._status_reporter())
        self.logger.info(f"Fingerprinter started (max_concurrent={self._max_concurrent})")

    async def _run(self) -> None:
        """Process items continuously, bounded by semaphore."""
        while self._running:
            try:
                item = await asyncio.wait_for(
                    self.input_queue.get(),
                    timeout=0.5
                )
                asyncio.create_task(self._process_item(item))
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                import traceback
                self.logger.error(f"Error in fingerprinter loop: {e}\n{traceback.format_exc()}")

    async def _process_item(self, item: tuple[str, int]) -> None:
        """Process a single item with semaphore protection."""
        async with self._semaphore:
            self._processing_count += 1
            try:
                result = await self.process(item)
                self._processed += 1

                if isinstance(result, CameraFingerprint):
                    await self.output_queue.put(result)
                    self._successful += 1
                    fp = result.fingerprint
                    evidence = f" [{fp.probe_method}]" if fp.probe_method else ""
                    self.logger.info(f"✓ {result.ip}:{result.port} - {fp.vendor or 'Unknown'} - {fp.model or ''}{evidence}")
                else:
                    self._failed += 1
            except Exception as e:
                import traceback
                self._processed += 1
                self._failed += 1
                self.logger.error(f"Error processing item: {e}")
            finally:
                self._processing_count -= 1

    async def process(self, item: tuple[str, int]) -> Optional[CameraFingerprint]:
        try:
            ip, port = item
            fp = await self._fingerprint(ip, port)
            if fp:
                result = CameraFingerprint(
                    ip=ip,
                    port=port,
                    fingerprint=fp,
                    weight=0.8
                )
                await self.storage.write("fingerprints", [result])
                return result
            return None
        except Exception as e:
            import traceback
            self.logger.error(f"Error processing {item[0]}:{item[1]}: {e}\n{traceback.format_exc()}")
            return None

    async def _fingerprint(self, ip: str, port: int) -> Optional[Fingerprint]:
        strategies = [
            lambda: self._optimistic_route(ip, port),
            lambda: self._sniffer_route(ip, port)
        ]

        for strategy in strategies:
            try:
                result = await strategy()
                if result:
                    return result
            except Exception as e:
                self.logger.debug(f"Fingerprint strategy failed for {ip}:{port}: {e}")
        return None

    async def _optimistic_route(self, ip: str, port: int) -> Optional[Fingerprint]:
        vendor_hint = None
        for module in self.modules:
            if port in module.supported_ports():
                result = await module.probe(ip, port, vendor_hint)
                if result:
                    if result.vendor:
                        vendor_hint = result.vendor
                    return result
        return None

    async def _sniffer_route(self, ip: str, port: int) -> Optional[Fingerprint]:
        try:
            banner = await asyncio.wait_for(
                self._read_banner(ip, port),
                timeout=2
            )
            if banner:
                return Fingerprint(
                    vendor="unknown",
                    raw_banner=banner[:256].decode(errors="ignore"),
                    services=["unknown"]
                )
        except Exception:
            pass
        return None

    async def _read_banner(self, ip: str, port: int) -> bytes:
        reader, writer = await asyncio.open_connection(ip, port, limit=256)
        banner = await reader.read(256)
        writer.close()
        await writer.wait_closed()
        return banner

    async def _status_reporter(self) -> None:
        """Periodically report progress."""
        while self._running:
            await asyncio.sleep(5)
            elapsed = asyncio.get_event_loop().time() - self._start_time
            rate = self._processed / elapsed if elapsed > 0 else 0
            queue_size = self.input_queue.size()

            self.logger.info(
                f"[Progress] Processed: {self._processed} | "
                f"Success: {self._successful} | "
                f"Failed: {self._failed} | "
                f"Queue: {queue_size} | "
                f"Active: {self._processing_count} | "
                f"Rate: {rate:.1f}/s"
            )

    async def stop(self) -> None:
        self._running = False

        # Wait for active processing to complete (with timeout)
        timeout = 30
        while self._processing_count > 0 and timeout > 0:
            await asyncio.sleep(1)
            timeout -= 1

        # Cancel status reporter
        if self._status_task:
            self._status_task.cancel()
            try:
                await self._status_task
            except asyncio.CancelledError:
                pass

        # Cancel main task
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        # Final status report
        elapsed = asyncio.get_event_loop().time() - self._start_time if self._start_time else 0
        rate = self._processed / elapsed if elapsed > 0 else 0

        self.logger.info(
            f"[Final] Processed: {self._processed} | "
            f"Success: {self._successful} | "
            f"Failed: {self._failed} | "
            f"Rate: {rate:.1f}/s"
        )