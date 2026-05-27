"""Discord bot interface for controlling the camera-scan pipeline."""
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

import discord
from discord.ext import commands
from discord import app_commands

from src.core.config import get_default_config
from src.pipeline.builder import PipelineBuilder, Pipeline
from src.layers import PortScanner, CIDRInputSource, Fingerprinter
from src.storage.sqlite_backend import SQLiteBackend
from src.core.durable_queue import DurableQueue


class ScanGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        # Gọi init của class cha để đặt tên group là /scan
        super().__init__(name="scan", description="Camera scan controls")
        self.bot = bot

    @app_commands.command(name="start", description="Start the camera scan pipeline")
    async def scan_start(self, interaction: discord.Interaction):
        if self.bot._status == "running":
            await interaction.response.send_message("Scan is already running.")
            return

        await interaction.response.send_message("Starting scan...")
        self.bot._scan_task = asyncio.create_task(self.bot._run_pipeline())

    @app_commands.command(name="pause", description="Pause the current scan")
    async def scan_pause(self, interaction: discord.Interaction):
        if self.bot._status != "running":
            await interaction.response.send_message("No scan is running.")
            return

        self.bot._status = "stopping"
        embed = self.bot._build_progress_embed()
        embed.title = "Scan Paused"
        embed.color = 0xFEE75C

        if self.bot.pipeline:
            asyncio.create_task(self.bot.pipeline.stop())

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="stop", description="Stop the current scan")
    async def scan_stop(self, interaction: discord.Interaction):
        if self.bot._status != "running":
            await interaction.response.send_message("No scan is running.")
            return

        self.bot._status = "stopping"
        embed = self.bot._build_progress_embed()
        embed.title = "Scan Stopped"
        embed.color = 0xED4245

        if self.bot.pipeline:
            asyncio.create_task(self.bot.pipeline.stop())

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="progress", description="Show current scan progress")
    async def scan_progress(self, interaction: discord.Interaction):
        if self.bot._status != "running" or not self.bot.scanner:
            await interaction.response.send_message("No scan is running.")
            return

        embed = self.bot._build_progress_embed()
        await interaction.response.send_message(embed=embed)


# --- CLASS BOT CHÍNH ---
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
        self._status = "idle"  # idle, running, stopping
        
        self.scan_group = ScanGroup(self)

    async def setup_hook(self):
        guild_id = os.environ.get("DISCORD_GUILD_ID") or os.environ.get("GUILD_ID")
        
        if guild_id:
            guild = discord.Object(id=int(guild_id))
            
            self.tree.clear_commands(guild=guild)
            self.tree.clear_commands(guild=None)
            await self.tree.sync(guild=None) 
            
            self.tree.add_command(self.scan_group, guild=guild)
            await self.tree.sync(guild=guild)
            print(f"ĐỒNG BỘ thành công vào Server ID: {guild_id}")
        else:
            self.tree.add_command(self.scan_group)
            await self.tree.sync()
            print("Đồng bộ Global.")

    async def _run_pipeline(self):
        """Build and run the pipeline to completion."""
        try:
            config = get_default_config()
            builder = PipelineBuilder(config)
            self.storage = builder.build_storage()
            queues = builder.build_queues(self.storage)

            self.scanner = PortScanner(
                config=config.layers,
                output_queue=queues[0],
                cidr_file="data/cidrs.txt",
                storage=self.storage,
            )
            self.fingerprinter = Fingerprinter(
                config=config.layer2,
                input_queue=queues[0],
                output_queue=queues[1],
                storage=self.storage,
            )

            input_source = CIDRInputSource("data/cidrs.txt")

            self.pipeline = Pipeline(
                layers=[self.scanner, self.fingerprinter],
                queues=queues,
                storage=self.storage,
                input_source=input_source,
            )

            await self.pipeline.start()
            self._status = "running"

            # Wait for scanner to finish
            if self.scanner._watcher_task:
                await self.scanner._watcher_task

            # Wait for fingerprinter to drain the queue
            while queues[0].size() > 0 and self.fingerprinter._running:
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Pipeline error: {e}")
        finally:
            if self.pipeline:
                await self.pipeline.stop()
            self._status = "idle"
            self.pipeline = None

    def _build_progress_embed(self) -> discord.Embed:
        embed = discord.Embed(title="Camera Scan Progress", color=0x5865F2)

        if self.scanner:
            elapsed = (
                asyncio.get_event_loop().time() - self.scanner._start_time
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
                asyncio.get_event_loop().time() - self.fingerprinter._start_time
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


if __name__ == "__main__":
    token = os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("BOT_TOKEN")
    if not token:
        print("Error: DISCORD_BOT_TOKEN or BOT_TOKEN environment variable is required")
        exit(1)

    bot = ScanBot()
    bot.run(token)