"""Main port scanner implementing Scanner interface."""
import asyncio
import re
from pathlib import Path
from typing import AsyncIterator, Optional
from src.core.interfaces import Scanner, InputSource
from src.core.queue_protocol import QueueProtocol
from src.core.config import Layer1Config
from src.storage.base import StorageBackend
from src.storage.schemas import PortScanResult
from src.utils.logging import setup_logger
from src.utils.network import count_total_ips


class CIDRInputSource(InputSource):
    def __init__(self, cidr_file: str):
        self.cidr_file = cidr_file

    async def read(self) -> AsyncIterator[str]:
        with open(self.cidr_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line


class PortScanner(Scanner):
    def __init__(
        self,
        config: Layer1Config,
        output_queue: QueueProtocol,
        cidr_file: str = "data/cidrs.txt",
        storage: Optional[StorageBackend] = None
    ):
        self.config = config
        self.output_queue = output_queue
        self.cidr_file = cidr_file
        self.storage = storage
        self.logger = setup_logger("PortScanner")
        self._watcher_task: Optional[asyncio.Task] = None
        self._status_task: Optional[asyncio.Task] = None
        self._running = False

        # Progress counters
        self._discovered = 0
        self._total_ips = 0
        self._scanned_ips = 0
        self._scan_percentage = 0
        self._stderr_task = None
        self._start_time = None
        self._num_ports = 4  # Will be updated from ports file

        # Subprocess management
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._masscan_done: Optional[asyncio.Event] = None

    async def start(self, input_source: InputSource) -> None:
        self._running = True
        self._start_time = asyncio.get_event_loop().time()
        self._masscan_done = asyncio.Event()
        self._watcher_task = asyncio.create_task(self._run_scanner(input_source))
        self._status_task = asyncio.create_task(self._status_reporter())

    async def _run_scanner(self, input_source: InputSource) -> None:
        output_path = Path(self.config.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cidr_list = [cidr async for cidr in input_source.read()]

        # Calculate total IPs from CIDR ranges
        self._total_ips = count_total_ips(cidr_list)
        self.logger.info(f"Total IPs to scan: {self._total_ips:,}")

        ports_file = Path("data/ports.txt")
        if ports_file.exists():
            with open(ports_file) as f:
                ports = ",".join(f.read().strip().split("\n"))
        else:
            ports = "80,554,8080,8554"

        cmd = [
            self.config.masscan_path,
            "-oL", str(output_path),
            "--output-flush",
            "--status",
            "--rate", str(self.config.scan_rate)
        ]
        cmd.extend(["-p", ports])
        cmd.extend(cidr_list)

        self.logger.info(f"Starting masscan: {' '.join(cmd)}")

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )

            self._stderr_task = asyncio.create_task(self._read_stderr(self._proc.stderr))

            # Run watcher — it exits when masscan finishes and file is fully drained
            await self._watch_and_feed(output_path)

            # Reap the process
            await self._proc.wait()
        except Exception as e:
            self.logger.error(f"Masscan error: {e}")
        finally:
            self._masscan_done.set()

    async def _watch_and_feed(self, output_path: Path) -> None:
        offset = 0
        batch = []

        try:
            # Wait for the output file to appear
            while self._running and not output_path.exists():
                if self._masscan_done.is_set():
                    return  # Masscan exited without creating the file
                await asyncio.sleep(0.5)

            if not self._running:
                return

            with open(output_path, "rb") as f:
                while self._running:
                    f.seek(offset)
                    chunk = f.read()

                    if not chunk:
                        if self._masscan_done.is_set():
                            break  # Masscan finished and file fully drained
                        await asyncio.sleep(0.1)
                        continue

                    # Handle partial last line
                    last_newline_idx = chunk.rfind(b'\n')
                    if last_newline_idx == -1:
                        await asyncio.sleep(0.1)
                        continue

                    complete_data = chunk[:last_newline_idx + 1]
                    offset += len(complete_data)

                    lines = complete_data.decode(errors='ignore').splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.startswith("open tcp"):
                            parts = line.split()
                            if len(parts) >= 5:
                                port = int(parts[2])
                                ip = parts[3]
                                batch.append((ip, port))
                                self._discovered += 1
                                if len(batch) >= 10:
                                    for item in batch:
                                        await self.output_queue.put(item)
                                    if self.storage:
                                        await self.storage.submit("port_scans", [
                                            PortScanResult(ip=ip, port=port) for ip, port in batch
                                        ])
                                    self.logger.debug(f"Batch: {len(batch)} IPs")
                                    batch = []

                    await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        finally:
            # Flush remaining batch
            if batch:
                for item in batch:
                    try:
                        await self.output_queue.put(item)
                    except Exception:
                        pass
                if self.storage:
                    await self.storage.submit("port_scans", [
                        PortScanResult(ip=ip, port=port) for ip, port in batch
                    ])

    async def _read_stderr(self, stderr) -> None:
        """Read masscan stderr for progress information."""
        percentage_pattern = re.compile(r'\[(\d+)%\]')
        hosts_pattern = re.compile(r'Scanning (\d+) hosts')
        rate_pattern = re.compile(r'rate: (\d+\.\d+)')

        while self._running:
            try:
                line = await stderr.readline()
                if not line:
                    break

                line_str = line.decode(errors='ignore').strip()

                # Log stderr lines for debugging
                self.logger.debug(f"Masscan stderr: {line_str}")

                # Parse percentage from stderr
                match = percentage_pattern.search(line_str)
                if match:
                    self._scan_percentage = int(match.group(1))
                    # Calculate scanned IPs from percentage
                    if self._total_ips > 0:
                        self._scanned_ips = int(self._total_ips * self._scan_percentage / 100)

                # Also parse "Scanning XXX hosts..."
                hosts_match = hosts_pattern.search(line_str)
                if hosts_match:
                    # Masscan reports current batch, update if larger
                    reported = int(hosts_match.group(1))
                    if reported > self._scanned_ips:
                        self._scanned_ips = reported

                # Parse rate to estimate progress
                rate_match = rate_pattern.search(line_str)
                if rate_match:
                    self.logger.debug(f"Masscan rate: {rate_match.group(1)}/s")

            except Exception:
                continue

    async def _status_reporter(self) -> None:
        """Periodically report scan progress."""
        while self._running:
            await asyncio.sleep(5)
            elapsed = asyncio.get_event_loop().time() - self._start_time
            rate = self._discovered / elapsed if elapsed > 0 else 0
            queue_size = self.output_queue.size()

            # Estimate progress from scan rate
            est_percentage = 0
            est_scanned = 0
            if self.config.scan_rate > 0 and self._total_ips > 0 and self._num_ports > 0:
                total_packets = self._total_ips * self._num_ports
                packets_sent = int(self.config.scan_rate * elapsed)
                est_percentage = min(100, int(packets_sent / total_packets * 100))
                est_scanned = int(self._total_ips * est_percentage / 100)

            # Use the higher of stderr-reported and estimated
            percentage = max(self._scan_percentage, est_percentage)
            scanned = max(self._scanned_ips, est_scanned)

            progress = f"{scanned:,}" if self._total_ips == 0 else f"{scanned:,} / {self._total_ips:,}"
            hit_rate = (self._discovered / scanned * 100) if scanned > 0 else 0
            self.logger.info(
                f"[Scan Progress] Scanned: {progress} ({percentage}%) | "
                f"Discovered: {self._discovered} | "
                f"Hit rate: {hit_rate:.2f}% | "
                f"Queue: {queue_size} | "
                f"Rate: {rate:.1f}/s | "
                f"Elapsed: {elapsed:.1f}s"
            )

    async def scan(self, input_source: InputSource) -> AsyncIterator[tuple[str, int]]:
        """Legacy scan method - kept for compatibility."""
        async for result in self._run_masscan_legacy(input_source):
            yield result

    async def _run_masscan_legacy(self, input_source: InputSource) -> AsyncIterator[tuple[str, int]]:
        output_path = Path(self.config.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cidr_list = [cidr async for cidr in input_source.read()]

        ports_file = Path("data/ports.txt")
        if ports_file.exists():
            with open(ports_file) as f:
                ports = ",".join(f.read().strip().split("\n"))
        else:
            ports = "80,554,8080,8554"

        cmd = [
            self.config.masscan_path,
            "-oL", str(output_path),
            "--output-flush",
            "--status",
            "--rate", str(self.config.scan_rate)
        ]
        cmd.extend(["-p", ports])
        cmd.extend(cidr_list)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        offset = 0
        while True:
            try:
                with open(output_path) as f:
                    f.seek(offset)
                    lines = f.readlines()
                    offset = f.tell()
                    for line in lines:
                        line = line.strip()
                        if line.startswith("open tcp"):
                            parts = line.split()
                            if len(parts) >= 5:
                                port = int(parts[2])
                                ip = parts[3]
                                yield (ip, port)
                await asyncio.sleep(0.1)
            except FileNotFoundError:
                await asyncio.sleep(0.5)

    async def stop(self) -> None:
        self._running = False

        # Signal completion so watcher can exit
        if self._masscan_done:
            self._masscan_done.set()

        # Terminate masscan subprocess
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
            except ProcessLookupError:
                pass

        # Cancel stderr reader
        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass

        # Cancel status reporter
        if self._status_task:
            self._status_task.cancel()
            try:
                await self._status_task
            except asyncio.CancelledError:
                pass

        # Cancel watcher
        if self._watcher_task:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except asyncio.CancelledError:
                pass

        # Final status
        elapsed = asyncio.get_event_loop().time() - self._start_time if self._start_time else 0
        rate = self._discovered / elapsed if elapsed > 0 else 0
        progress = f"{self._scanned_ips:,}" if self._total_ips == 0 else f"{self._scanned_ips:,} / {self._total_ips:,}"
        hit_rate = (self._discovered / self._scanned_ips * 100) if self._scanned_ips > 0 else 0
        self.logger.info(
            f"[Scan Complete] Total discovered: {self._discovered} | "
            f"Scanned: {progress} ({self._scan_percentage}%) | "
            f"Hit rate: {hit_rate:.2f}% | "
            f"Rate: {rate:.1f}/s | "
            f"Time: {elapsed:.1f}s"
        )
