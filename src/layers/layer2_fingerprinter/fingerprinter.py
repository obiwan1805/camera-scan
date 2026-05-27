"""Main fingerprinter implementing Filter interface with semaphore-based processing."""
import asyncio
from typing import Optional
from src.core.interfaces import Filter
from src.core.queue_protocol import QueueProtocol
from src.storage.base import StorageBackend
from src.storage.schemas import CameraFingerprint, Fingerprint, RawResponse
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
        self._skipped = 0
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
                # Skip items already fingerprinted (resume dedup)
                ip, port = item
                if await self.storage.has_fingerprint(ip, port):
                    if hasattr(self.input_queue, 'ack'):
                        await self.input_queue.ack(item)
                    self._processed += 1
                    self._skipped += 1
                    return

                result = await self.process(item)
                self._processed += 1

                if isinstance(result, CameraFingerprint):
                    await self.output_queue.put(result)
                    if hasattr(self.input_queue, 'ack'):
                        await self.input_queue.ack(item)
                    self._successful += 1
                    fp = result.fingerprint
                    evidence = f" [{fp.probe_method}]" if fp.probe_method else ""
                    self.logger.info(f"✓ {result.ip}:{result.port} - {fp.vendor or 'Unknown'} - {fp.model or ''}{evidence}")
                else:
                    if hasattr(self.input_queue, 'mark_failed'):
                        await self.input_queue.mark_failed(item)
                    self._failed += 1
            except Exception as e:
                import traceback
                self._processed += 1
                self._failed += 1
                if hasattr(self.input_queue, 'mark_failed'):
                    await self.input_queue.mark_failed(item)
                self.logger.error(f"Error processing item: {e}")
            finally:
                self._processing_count -= 1

    async def process(self, item: tuple[str, int]) -> Optional[CameraFingerprint]:
        try:
            ip, port = item
            fp, raw_responses = await self._fingerprint(ip, port)

            if raw_responses:
                await self.storage.submit("raw_responses", raw_responses)

            if fp:
                result = CameraFingerprint(
                    ip=ip,
                    port=port,
                    fingerprint=fp,
                    weight=0.8
                )
                await self.storage.submit("fingerprints", [result])
                return result
            return None
        except Exception as e:
            import traceback
            self.logger.error(f"Error processing {item[0]}:{item[1]}: {e}\n{traceback.format_exc()}")
            return None

    async def _fingerprint(self, ip: str, port: int) -> tuple[Optional[Fingerprint], list[RawResponse]]:
        """Returns (fingerprint_or_none, collected_raw_responses)."""
        all_raw: list[RawResponse] = []

        fp, raw = await self._optimistic_route(ip, port)
        all_raw.extend(raw)
        if fp:
            return fp, all_raw

        fp, raw = await self._sniffer_route(ip, port)
        all_raw.extend(raw)
        if fp:
            return fp, all_raw

        return None, all_raw

    async def _optimistic_route(self, ip: str, port: int) -> tuple[Optional[Fingerprint], list[RawResponse]]:
        """Try each module. Returns (fingerprint_or_none, collected_raw_responses)."""
        vendor_hint = None
        all_raw: list[RawResponse] = []
        for module in self.modules:
            if port in module.supported_ports():
                result = await module.probe(ip, port, vendor_hint)
                if result:
                    all_raw.extend(result.raw_responses)
                    if result.fingerprint:
                        if result.fingerprint.vendor:
                            vendor_hint = result.fingerprint.vendor
                        return result.fingerprint, all_raw
        return None, all_raw

    async def _sniffer_route(self, ip: str, port: int) -> tuple[Optional[Fingerprint], list[RawResponse]]:
        try:
            banner = await asyncio.wait_for(
                self._read_banner(ip, port),
                timeout=2
            )
            if banner:
                raw = RawResponse(
                    ip=ip, port=port, module="banner", endpoint="/",
                    raw_data=banner
                )
                return Fingerprint(
                    vendor="unknown",
                    raw_banner=banner[:256].decode(errors="ignore"),
                    services=["unknown"]
                ), [raw]
        except Exception:
            pass
        return None, []

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
                f"Skipped: {self._skipped} | "
                f"Queue: {queue_size} | "
                f"Active: {self._processing_count} | "
                f"Rate: {rate:.1f}/s"
            )

    async def stop(self) -> None:
        self._running = False

        timeout = 30
        while self._processing_count > 0 and timeout > 0:
            await asyncio.sleep(1)
            timeout -= 1

        if self._status_task:
            self._status_task.cancel()
            try:
                await self._status_task
            except asyncio.CancelledError:
                pass

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        elapsed = asyncio.get_event_loop().time() - self._start_time if self._start_time else 0
        rate = self._processed / elapsed if elapsed > 0 else 0

        self.logger.info(
            f"[Final] Processed: {self._processed} | "
            f"Success: {self._successful} | "
            f"Failed: {self._failed} | "
            f"Skipped: {self._skipped} | "
            f"Rate: {rate:.1f}/s"
        )