"""Main fingerprinter -- orchestrates collect/match/resolve pipeline."""
import asyncio
from typing import Optional
from src.core.interfaces import Filter
from src.core.queue_protocol import QueueProtocol
from src.storage.base import StorageBackend
from src.storage.schemas import CameraFingerprint, Fingerprint, RawResponse
from src.core.config import Layer2Config
from src.layers.layer2_fingerprinter.signatures.loader import SignatureLoader
from src.layers.layer2_fingerprinter.engine import SignatureEngine
from src.layers.layer2_fingerprinter.resolver import AggregationResolver
from src.layers.layer2_fingerprinter.probers import (
    HTTPProber, HTTPSProber, RTSPProber, ONVIFProber, FaviconProber,
)
from src.layers.layer2_fingerprinter.probers.types import CollectedData
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
        self._max_concurrent = config.worker_pool.max_concurrent or 200
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._status_task: Optional[asyncio.Task] = None

        # Load signatures and build engine
        sig_dir = getattr(config, 'signatures_dir', 'config/signatures')
        self._loader = SignatureLoader(sig_dir)
        self._engine = SignatureEngine(self._loader.signatures)
        self._resolver = AggregationResolver()

        # Build probers with signature-driven endpoints
        endpoints = self._loader.get_unique_endpoint_paths()
        rtsp_paths = self._loader.get_all_rtsp_paths()
        timeout = getattr(config, 'prober_timeout', 10)

        self._probers = [
            HTTPProber(endpoint_paths=endpoints, timeout=timeout),
            HTTPSProber(endpoint_paths=endpoints, timeout=timeout),
            RTSPProber(extra_paths=rtsp_paths, timeout=timeout),
            ONVIFProber(timeout=timeout),
            FaviconProber(timeout=timeout),
        ]

        # Progress counters
        self._processed = 0
        self._successful = 0
        self._failed = 0
        self._skipped = 0
        self._start_time = None
        self._active_tasks: set[asyncio.Task] = set()
        self._reload_task: Optional[asyncio.Task] = None

    @property
    def _processing_count(self) -> int:
        return len(self._active_tasks)

    async def start(self) -> None:
        self._running = True
        self._start_time = asyncio.get_running_loop().time()
        self._task = asyncio.create_task(self._run())
        self._status_task = asyncio.create_task(self._status_reporter())
        self._reload_task = asyncio.create_task(self._sig_watcher())
        self.logger.info(f"Fingerprinter started (max_concurrent={self._max_concurrent}, signatures={len(self._loader.signatures)})")

    async def _run(self) -> None:
        """Process items continuously, bounded by semaphore."""
        while self._running:
            try:
                item = await asyncio.wait_for(
                    self.input_queue.get(),
                    timeout=0.5
                )
                await self._semaphore.acquire()
                task = asyncio.create_task(self._process_item_with_semaphore(item))
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                import traceback
                self.logger.error(f"Error in fingerprinter loop: {e}\n{traceback.format_exc()}")

    async def _process_item_with_semaphore(self, item: tuple[str, int]) -> None:
        """Process a single item — semaphore already acquired in _run."""
        try:
            await self._process_item(item)
        finally:
            self._semaphore.release()

    async def _process_item(self, item: tuple[str, int]) -> None:
        """Process a single item."""
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
                cves = f" cves={fp.cves}" if fp.cves else ""
                self.logger.info(
                    f"[OK] {result.ip}:{result.port} - "
                    f"{fp.vendor or 'Unknown'} - {fp.model or ''} "
                    f"{fp.version or ''}{cves}"
                )
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

    async def process(self, item: tuple[str, int]) -> Optional[CameraFingerprint]:
        try:
            ip, port = item
            fp, raw_responses, protocols = await self._fingerprint(ip, port)

            if raw_responses and getattr(self.config, 'log_raw_responses', False):
                await self.storage.submit("raw_responses", raw_responses)

            if fp:
                weight = self._calculate_weight(fp)
                result = CameraFingerprint(
                    ip=ip,
                    port=port,
                    fingerprint=fp,
                    weight=weight,
                    protocol="+".join(sorted(set(protocols))) or None,
                )
                await self.storage.submit("fingerprints", [result])
                return result
            return None
        except Exception as e:
            import traceback
            self.logger.error(f"Error processing {item[0]}:{item[1]}: {e}\n{traceback.format_exc()}")
            return None

    async def _fingerprint(self, ip: str, port: int) -> tuple[Optional[Fingerprint], list[RawResponse], list[str]]:
        """Three-phase pipeline: collect -> match -> resolve."""
        # Phase 1: Collect raw data via all applicable probers concurrently
        collected = await self._collect(ip, port)

        # Phase 2: Run ALL signatures against collected data
        matches = self._engine.match(collected)

        # Phase 3: Aggregate matches into best fingerprint
        fp = self._resolver.resolve(matches)

        return fp, collected.raw_responses, collected.protocols

    async def _collect(self, ip: str, port: int) -> CollectedData:
        """Run all applicable probers concurrently and merge results."""
        applicable = [p for p in self._probers if port in p.supported_ports()]
        if not applicable:
            return CollectedData(ip=ip, port=port)

        async def _run_prober(prober):
            try:
                return await prober.probe(ip, port, CollectedData(ip=ip, port=port))
            except Exception:
                return None

        results = await asyncio.gather(*[_run_prober(p) for p in applicable])

        collected = CollectedData(ip=ip, port=port)
        for prober, partial in zip(applicable, results):
            if partial is None:
                continue
            if partial.html and not collected.html:
                collected.html = partial.html
            collected.headers.update(partial.headers)
            collected.xml_texts.extend(partial.xml_texts)
            collected.json_texts.extend(partial.json_texts)
            if partial.rtsp_banner and not collected.rtsp_banner:
                collected.rtsp_banner = partial.rtsp_banner
            if partial.onvif_response and not collected.onvif_response:
                collected.onvif_response = partial.onvif_response
            if partial.favicon_hash is not None:
                collected.favicon_hash = partial.favicon_hash
            if partial.ssl_subject and not collected.ssl_subject:
                collected.ssl_subject = partial.ssl_subject
            collected.raw_responses.extend(partial.raw_responses)

            if prober.protocol and (
                partial.html
                or partial.headers
                or partial.xml_texts
                or partial.json_texts
                or partial.rtsp_banner
                or partial.onvif_response
                or partial.favicon_hash is not None
                or partial.ssl_subject
            ):
                collected.protocols.append(prober.protocol)

        return collected

    async def _status_reporter(self) -> None:
        """Periodically report progress."""
        cleanup_counter = 0
        while self._running:
            await asyncio.sleep(5)
            elapsed = asyncio.get_running_loop().time() - self._start_time
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

            # Periodically clean up old claims
            cleanup_counter += 1
            if cleanup_counter >= 12:  # every ~60 seconds
                cleanup_counter = 0
                try:
                    await self.storage.cleanup_claims(max_age_hours=24)
                except Exception:
                    pass

    def _calculate_weight(self, fp: Fingerprint) -> float:
        """Weight based on what was actually extracted.

        model + version = 1.0 (fully identified)
        model only      = 0.7
        version only    = 0.4
        neither         = 0.0
        """
        has_model = fp.model is not None
        has_version = fp.version is not None

        if has_model and has_version:
            return 1.0
        if has_model:
            return 0.7
        if has_version:
            return 0.4
        return 0.0

    async def _sig_watcher(self) -> None:
        """Periodically check for signature file changes and hot-reload."""
        while self._running:
            await asyncio.sleep(30)
            try:
                await self.reload_signatures()
            except Exception as e:
                self.logger.error(f"Signature hot-reload failed: {e}")

    async def reload_signatures(self) -> bool:
        """Reload signatures from disk and swap engine atomically.

        Called automatically every 30s by _sig_watcher, or manually via
        bot /signature reload. Returns True if signatures changed.
        """
        old_count = len(self._loader.signatures)
        old_hashes = self._sig_file_hashes()

        before, after = self._loader.reload()
        new_hashes = self._sig_file_hashes()

        if new_hashes == old_hashes:
            return False

        # Swap engine -- new targets get the new signatures immediately
        self._engine = SignatureEngine(self._loader.signatures)
        self.logger.info(
            f"Signatures hot-reloaded: {old_count} -> {len(self._loader.signatures)} vendors"
        )
        return True

    def _sig_file_hashes(self) -> dict:
        """MTimes of all signature YAML files for change detection."""
        result = {}
        sig_dir = self._loader._dir
        if sig_dir.exists():
            for f in sorted(sig_dir.glob("*.yaml")):
                result[f.name] = f.stat().st_mtime
        return result

    async def stop(self, **kwargs) -> None:
        self._running = False

        # Wait for in-flight tasks to complete
        if self._active_tasks:
            await asyncio.wait(self._active_tasks, timeout=30)

        # Close prober sessions
        for prober in self._probers:
            try:
                await prober.close()
            except Exception:
                pass

        if self._status_task:
            self._status_task.cancel()
            try:
                await self._status_task
            except asyncio.CancelledError:
                pass

        if self._reload_task:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        elapsed = asyncio.get_running_loop().time() - self._start_time if self._start_time else 0
        rate = self._processed / elapsed if elapsed > 0 else 0

        self.logger.info(
            f"[Final] Processed: {self._processed} | "
            f"Success: {self._successful} | "
            f"Failed: {self._failed} | "
            f"Skipped: {self._skipped} | "
            f"Rate: {rate:.1f}/s"
        )
