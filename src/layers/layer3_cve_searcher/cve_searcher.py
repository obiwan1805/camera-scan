"""CVESearcher — Layer 3 orchestrator that enriches fingerprints with CVE data."""
import asyncio
from typing import Optional
from src.core.interfaces import Filter
from src.core.config import Layer3Config
from src.core.queue_protocol import QueueProtocol
from src.storage.base import StorageBackend
from src.storage.schemas import CameraFingerprint
from src.utils.logging import setup_logger

from .auth_checker import AuthChecker
from .router import WeightRouter
from .strategies.nvd_strategy import HighConfidenceStrategy
from .strategies.msf_strategy import LowConfidenceStrategy
from .clients.nvd_client import NVDClient
from .clients.msf_rpc_client import MSFRPCClient


class CVESearcher(Filter):
    """Layer 3 CVE Searcher — consumes CameraFingerprint, enriches with CVE data."""

    def __init__(
        self,
        config: Layer3Config,
        input_queue: Optional[QueueProtocol] = None,
        output_queue: Optional[QueueProtocol] = None,
        storage: Optional[StorageBackend] = None,
    ):
        self.config = config
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.storage = storage
        self._logger = setup_logger("CVESearcher")

        self._target_semaphore = asyncio.Semaphore(config.target_concurrency)
        self._module_semaphore = asyncio.Semaphore(config.module_concurrency)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._status_task: Optional[asyncio.Task] = None

        self._router = WeightRouter()
        self._high_strategy = HighConfidenceStrategy()
        self._low_strategy = LowConfidenceStrategy(self._module_semaphore)

        self._nvd_client: Optional[NVDClient] = None
        self._msf_client: Optional[MSFRPCClient] = None

        self._auth_checker: Optional[AuthChecker] = None
        if config.auth.enabled:
            self._auth_checker = AuthChecker(config.auth, msf_client=None)

        self._auth_checked = 0
        self._auth_found = 0

        # Progress counters
        self._processed = 0
        self._cve_found = 0
        self._skipped = 0
        self._failed = 0
        self._start_time = None
        self._active_tasks: set = set()

    @property
    def _processing_count(self) -> int:
        return len(self._active_tasks)

    async def start(self) -> None:
        self._running = True
        self._start_time = asyncio.get_running_loop().time()

        # Init NVD client
        self._nvd_client = NVDClient(self.config.nvd)

        # Connect to msfrpcd
        self._msf_client = MSFRPCClient(self.config.msf)
        try:
            await self._msf_client.connect()
        except Exception as e:
            self._logger.warning(f"msfrpcd connection failed: {e}. MSF check unavailable.")

        if self._auth_checker and self._msf_client:
            self._auth_checker._msf._msf_client = self._msf_client

        self._task = asyncio.create_task(self._run())
        self._status_task = asyncio.create_task(self._status_reporter())
        self._logger.info(
            f"CVESearcher started (concurrency={self.config.target_concurrency}, "
            f"msf={self.config.msf.host}:{self.config.msf.port})"
        )

    async def _run(self) -> None:
        """Process items continuously, bounded by semaphore."""
        while self._running:
            try:
                item = await asyncio.wait_for(self.input_queue.get(), timeout=0.5)
                await self._target_semaphore.acquire()
                task = asyncio.create_task(self._process_item_with_semaphore(item))
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self._logger.error(f"Error in CVE searcher loop: {e}")

    async def _process_item_with_semaphore(self, item: CameraFingerprint) -> None:
        try:
            await self._process_item(item)
        finally:
            self._target_semaphore.release()

    async def _process_item(self, item: CameraFingerprint) -> None:
        try:
            # Skip if already has CVEs (resume dedup)
            if item.fingerprint.cves:
                if hasattr(self.input_queue, 'ack'):
                    await self.input_queue.ack((item.ip, item.port))
                self._processed += 1
                self._skipped += 1
                return

            result = await self.process(item)
            self._processed += 1

            if result:
                await self.storage.submit("fingerprints", [result])
                if hasattr(self.input_queue, 'ack'):
                    await self.input_queue.ack((item.ip, item.port))
                if result.fingerprint.cves:
                    self._cve_found += 1
            else:
                self._failed += 1
        except Exception as e:
            self._processed += 1
            self._failed += 1
            self._logger.error(f"Error processing {item.ip}:{item.port}: {e}")

    async def process(self, item: CameraFingerprint) -> Optional[CameraFingerprint]:
        """Process a CameraFingerprint: CVE search + auth check in parallel."""
        strategy_type = self._router.classify(item)

        async def _cve_search():
            if strategy_type == "skip":
                self._logger.info(f"[SKIP] {item.ip}:{item.port} — no vendor")
                return item
            try:
                if strategy_type == "high":
                    return await self._high_strategy.execute(
                        item, self._nvd_client, self._msf_client, self.storage
                    )
                else:
                    return await self._low_strategy.execute(
                        item, self._nvd_client, self._msf_client, self.storage
                    )
            except Exception as e:
                self._logger.error(f"Strategy error for {item.ip}:{item.port}: {e}")
                return item

        async def _auth_check():
            if not self._auth_checker:
                return []
            try:
                return await self._auth_checker.check(item)
            except Exception as e:
                self._logger.warning(f"Auth check failed for {item.ip}:{item.port}: {e}")
                return []

        cve_result, auth_result = await asyncio.gather(_cve_search(), _auth_check())

        result = cve_result if cve_result is not None else item
        result.auth_info = auth_result

        if auth_result:
            self._auth_checked += 1
            if any(a.has_login for a in auth_result):
                self._auth_found += 1

        return result

    async def _status_reporter(self) -> None:
        while self._running:
            await asyncio.sleep(5)
            elapsed = asyncio.get_running_loop().time() - self._start_time
            rate = self._processed / elapsed if elapsed > 0 else 0
            self._logger.info(
                f"[Progress] Processed: {self._processed} | "
                f"CVE found: {self._cve_found} | "
                f"Auth checked: {self._auth_checked} | "
                f"Auth found: {self._auth_found} | "
                f"Skipped: {self._skipped} | "
                f"Failed: {self._failed} | "
                f"Active: {self._processing_count} | "
                f"Rate: {rate:.1f}/s"
            )

    async def stop(self, **kwargs) -> None:
        self._running = False

        if self._active_tasks:
            await asyncio.wait(self._active_tasks, timeout=30)

        if self._nvd_client:
            await self._nvd_client.close()

        if self._msf_client:
            try:
                await self._msf_client.disconnect()
            except Exception:
                pass

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

        elapsed = asyncio.get_running_loop().time() - self._start_time if self._start_time else 0
        rate = self._processed / elapsed if elapsed > 0 else 0
        self._logger.info(
            f"[Final] Processed: {self._processed} | "
            f"CVE found: {self._cve_found} | "
            f"Skipped: {self._skipped} | "
            f"Failed: {self._failed} | "
            f"Rate: {rate:.1f}/s"
        )
