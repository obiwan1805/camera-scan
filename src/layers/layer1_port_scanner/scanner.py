"""Main port scanner implementing Scanner interface."""
import asyncio
import re
from pathlib import Path
from typing import AsyncIterator, Optional
from src.core.interfaces import Scanner, InputSource
from src.core.queue_protocol import QueueProtocol
from src.core.config import Layer1Config
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
        cidr_file: str = "data/cidrs.txt"
    ):
        self.config = config
        self.output_queue = output_queue
        self.cidr_file = cidr_file
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

    async def start(self, input_source: InputSource) -> None:
        self._running = True
        self._start_time = asyncio.get_event_loop().time()
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
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Start stderr reader for progress
            self._stderr_task = asyncio.create_task(self._read_stderr(proc.stderr))

            await asyncio.gather(
                self._watch_and_feed(output_path),
                proc.wait()
            )
        except Exception as e:
            self.logger.error(f"Masscan error: {e}")

    async def _watch_and_feed(self, output_path: Path) -> None:
        offset = 0
        batch = []
        while self._running:
            try:
                with open(output_path) as f:
                    f.seek(offset)
                    lines = f.readlines()
                    offset = f.tell()
                    for line in lines:
                        line = line.strip()
                        # masscan format: "open tcp PORT IP TIMESTAMP"
                        if line.startswith("open tcp"):
                            parts = line.split()
                            if len(parts) >= 5:
                                port = int(parts[2])
                                ip = parts[3]
                                batch.append((ip, port))
                                self._discovered += 1
                                # Batch processing to reduce queue operations
                                if len(batch) >= 10:
                                    for item in batch:
                                        await self.output_queue.put(item)
                                    self.logger.debug(f"Batch: {len(batch)} IPs")
                                    batch = []

                    # Flush remaining items in batch
                    if batch:
                        for item in batch:
                            await self.output_queue.put(item)
                        batch = []

                await asyncio.sleep(0.1)
            except FileNotFoundError:
                await asyncio.sleep(0.5)

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

            # If no progress from stderr, estimate from rate
            if self._scan_percentage == 0 and self.config.scan_rate > 0:
                # Packets sent = rate * elapsed
                # Each IP:port = 1 packet (approximately)
                # Total packets to scan = total_ips * num_ports
                if self._total_ips > 0 and self._num_ports > 0:
                    total_packets = self._total_ips * self._num_ports
                    packets_sent = int(self.config.scan_rate * elapsed)
                    percentage = min(100, int(packets_sent / total_packets * 100))
                    scanned = int(self._total_ips * percentage / 100)
                    self._scanned_ips = scanned
                    self._scan_percentage = percentage
                else:
                    percentage = 0
                    scanned = 0
            else:
                percentage = self._scan_percentage
                scanned = self._scanned_ips

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