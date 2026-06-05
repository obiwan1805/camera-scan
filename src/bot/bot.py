"""ScanBot — Discord bot for controlling the camera-scan pipeline."""
import os
import gc
import asyncio
import traceback
from pathlib import Path

import discord
from discord.ext import commands

from src.core.config import get_default_config
from src.pipeline.builder import PipelineBuilder, Pipeline
from src.layers import PortScanner, CIDRInputSource, Fingerprinter
from src.storage.sqlite_backend import SQLiteBackend
from src.core.durable_queue import DurableQueue

from .scan import ScanGroup
from .config import ConfigGroup
from .poc import PoCGroup
from .dict import DictGroup
from .target import TargetGroup
from .signature import SignatureGroup


class ScanBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True

        super().__init__(command_prefix="!", intents=intents)

        self.pipeline: Pipeline | None = None
        self.scanner: PortScanner | None = None
        self.fingerprinter: Fingerprinter | None = None
        self.storage: SQLiteBackend | None = None
        self._scan_task: asyncio.Task | None = None
        self._status = "idle"
        self._stop_signal = False
        self._delete_paused = False
        self._overrides: dict[str, int] = {}
        self._sig_loader = None

        self._command_groups = [
            ScanGroup(self), ConfigGroup(self),
            PoCGroup(self), DictGroup(self), TargetGroup(self),
            SignatureGroup(self),
        ]

    async def setup_hook(self):
        # Persistent storage for CRUD commands — lives for bot's entire lifetime
        self.db = SQLiteBackend()
        await self.db.connect()

        guild_id = os.environ.get("DISCORD_GUILD_ID") or os.environ.get("GUILD_ID")

        if guild_id:
            guild = discord.Object(id=int(guild_id))

            self.tree.clear_commands(guild=guild)
            self.tree.clear_commands(guild=None)
            await self.tree.sync(guild=None)

            for group in self._command_groups:
                self.tree.add_command(group, guild=guild)
            await self.tree.sync(guild=guild)
            print(f"Synced commands to Server ID: {guild_id}")
        else:
            for group in self._command_groups:
                self.tree.add_command(group)
            await self.tree.sync()
            print("Synced commands globally.")

    async def _run_pipeline(self):
        """Build and run the pipeline to completion. Only place that calls pipeline.stop()."""
        try:
            config = get_default_config()
            if "scan_rate" in self._overrides:
                config.layers.scan_rate = self._overrides["scan_rate"]
            if "masscan_wait" in self._overrides:
                config.layers.wait = self._overrides["masscan_wait"]
            if "max_concurrent" in self._overrides:
                config.layer2.worker_pool.max_concurrent = self._overrides["max_concurrent"]
            if "prober_timeout" in self._overrides:
                config.layer2.prober_timeout = self._overrides["prober_timeout"]
            if "batch_size" in self._overrides:
                config.layers.batch_size = self._overrides["batch_size"]

            builder = PipelineBuilder(config)
            self.storage = builder.build_storage()
            queues = builder.build_queues(self.storage)

            self.scanner = PortScanner(
                config=config.layers,
                output_queue=queues[0],
                storage=self.storage,
            )
            self.fingerprinter = Fingerprinter(
                config=config.layer2,
                input_queue=queues[0],
                output_queue=queues[1],
                storage=self.storage,
            )

            rows = await self.db.generic_list("targets")
            targets = [r["target"] for r in rows]
            input_source = CIDRInputSource(targets)

            self.pipeline = Pipeline(
                layers=[self.scanner, self.fingerprinter],
                queues=queues,
                storage=self.storage,
                input_source=input_source,
            )

            await self.pipeline.start()
            self._status = "running"
            self._stop_signal = False

            # Wait for scanner to finish OR stop signal
            if self.scanner._watcher_task:
                stop_event = asyncio.create_task(self._wait_stop_signal())
                done, _ = await asyncio.wait(
                    [self.scanner._watcher_task, stop_event],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                stop_event.cancel()

            # Wait for fingerprinter to drain the queue OR stop signal
            while (queues[0].size() > 0 and self.fingerprinter._running
                   and not self._stop_signal):
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Pipeline error: {e}")
            traceback.print_exc()
        finally:
            if self.pipeline:
                await self.pipeline.stop(resume=not self._delete_paused)
            if self._delete_paused:
                paused = Path("paused.conf")
                if paused.exists():
                    paused.unlink()
                    print("[Bot] Deleted paused.conf — next scan starts fresh")
            self._status = "idle"
            self._stop_signal = False
            self._delete_paused = False
            self.pipeline = None
            self.scanner = None
            self.fingerprinter = None
            self.storage = None
            gc.collect()

    async def _wait_stop_signal(self):
        while not self._stop_signal:
            await asyncio.sleep(0.5)

    async def _run_masscan_import(self, import_file: str) -> None:
        """Run standalone fingerprinter pipeline for imported masscan output."""
        import_path = Path(import_file)
        try:
            config = get_default_config()
            if "max_concurrent" in self._overrides:
                config.layer2.worker_pool.max_concurrent = self._overrides["max_concurrent"]
            if "prober_timeout" in self._overrides:
                config.layer2.prober_timeout = self._overrides["prober_timeout"]
            if "import_feed_batch" in self._overrides:
                config.layer2.import_feed_batch = self._overrides["import_feed_batch"]
            if "import_feed_interval" in self._overrides:
                config.layer2.import_feed_interval = self._overrides["import_feed_interval"]

            builder = PipelineBuilder(config)
            self.storage = builder.build_storage()
            await self.storage.connect()
            queues = builder.build_queues(self.storage)

            self.fingerprinter = Fingerprinter(
                config=config.layer2,
                input_queue=queues[0],
                output_queue=queues[1],
                storage=self.storage,
            )

            await self.fingerprinter.start()
            self._status = "running"
            self._stop_signal = False

            # Feed from file using configured batch/interval
            from src.layers import PortScanner
            feed_batch = config.layer2.import_feed_batch
            feed_interval = config.layer2.import_feed_interval
            batch = []
            total_fed = 0
            with open(import_path) as f:
                for line in f:
                    if self._stop_signal:
                        break
                    result = PortScanner.parse_masscan_line(line)
                    if result:
                        ip, port = result
                        batch.append((ip, port))
                        if len(batch) >= feed_batch:
                            if self.storage:
                                from src.storage.schemas import PortScanResult
                                await self.storage.submit("port_scans", [
                                    PortScanResult(ip=ip, port=port) for ip, port in batch
                                ])
                            for item in batch:
                                await queues[0].put(item)
                            total_fed += len(batch)
                            batch = []
                            if not self._stop_signal:
                                await asyncio.sleep(feed_interval)

            # Flush remaining
            if batch:
                if self.storage:
                    from src.storage.schemas import PortScanResult
                    await self.storage.submit("port_scans", [
                        PortScanResult(ip=ip, port=port) for ip, port in batch
                    ])
                for item in batch:
                    await queues[0].put(item)
                total_fed += len(batch)

            print(f"[Import] Fed {total_fed:,} entries to fingerprinter")

            # Wait for fingerprinter to finish OR stop signal
            while self.fingerprinter._running and not self._stop_signal:
                if queues[0].size() == 0 and self.fingerprinter._processing_count == 0:
                    break
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Masscan import error: {e}")
            traceback.print_exc()
        finally:
            if import_path.exists():
                import_path.unlink()
            if self.fingerprinter:
                fp = self.fingerprinter
                print(
                    f"[Import Complete] Processed: {fp._processed:,} | "
                    f"Successful: {fp._successful:,} | "
                    f"Failed: {fp._failed:,} | "
                    f"Skipped: {fp._skipped:,}"
                )
                await self.fingerprinter.stop()
            self._status = "idle"
            self._stop_signal = False
            self._delete_paused = False
            self.fingerprinter = None
            self.storage = None
            gc.collect()

    def _build_progress_embed(self) -> discord.Embed:
        embed = discord.Embed(title="Camera Scan Progress", color=0x5865F2)

        if self.scanner:
            elapsed = (
                asyncio.get_running_loop().time() - self.scanner._start_time
                if self.scanner._start_time
                else 0
            )
            total = self.scanner._total_ips
            scanned = self.scanner._scanned_ips
            percentage = self.scanner._scan_percentage
            discovered = self.scanner._discovered
            hit_rate = (discovered / scanned * 100) if scanned > 0 else 0

            progress_str = (
                f"{scanned:,} / {total:,} ({percentage}%)"
                if total > 0
                else f"{scanned:,}"
            )
            layer1 = (
                f"Scanned:    {progress_str}\n"
                f"Discovered: {discovered:,}\n"
                f"Hit rate:   {hit_rate:.2f}%\n"
                f"Elapsed:    {elapsed:.1f}s"
            )
            embed.add_field(
                name="Layer 1 — Port Scanner", value=f"```\n{layer1}\n```", inline=False
            )

        if self.fingerprinter:
            processed = self.fingerprinter._processed
            successful = self.fingerprinter._successful
            failed = self.fingerprinter._failed
            skipped = self.fingerprinter._skipped
            active = self.fingerprinter._processing_count
            elapsed = (
                asyncio.get_running_loop().time() - self.fingerprinter._start_time
                if self.fingerprinter._start_time
                else 0
            )
            rate = processed / elapsed if elapsed > 0 else 0

            layer2 = (
                f"Processed:  {processed:,}\n"
                f"Successful: {successful:,}\n"
                f"Failed:     {failed:,}\n"
                f"Skipped:    {skipped:,}\n"
                f"Active:     {active}\n"
                f"Rate:       {rate:.1f}/s"
            )
            embed.add_field(
                name="Layer 2 — Fingerprinter",
                value=f"```\n{layer2}\n```",
                inline=False,
            )

        return embed

    def _build_config_embed(self) -> discord.Embed:
        defaults = get_default_config()
        scan_rate = self._overrides.get("scan_rate", defaults.layers.scan_rate)
        masscan_wait = self._overrides.get("masscan_wait", defaults.layers.wait)
        max_concurrent = self._overrides.get("max_concurrent", defaults.layer2.worker_pool.max_concurrent)
        prober_timeout = self._overrides.get("prober_timeout", defaults.layer2.prober_timeout)
        feed_batch = self._overrides.get("import_feed_batch", defaults.layer2.import_feed_batch)
        feed_interval = self._overrides.get("import_feed_interval", defaults.layer2.import_feed_interval)

        embed = discord.Embed(title="Current Config", color=0x57F287)

        layer1 = (
            f"scan_rate:      {scan_rate:,} pps\n"
            f"masscan_wait:   {masscan_wait}s"
        )
        embed.add_field(name="Layer 1 — Masscan", value=f"```\n{layer1}\n```", inline=False)

        layer2 = (
            f"max_concurrent:       {max_concurrent}\n"
            f"prober_timeout:       {prober_timeout}s\n"
            f"import_feed_batch:    {feed_batch}\n"
            f"import_feed_interval: {feed_interval}s"
        )
        embed.add_field(name="Layer 2 — Fingerprinter", value=f"```\n{layer2}\n```", inline=False)

        embed.set_footer(text="All values apply on next /scan start")
        return embed
