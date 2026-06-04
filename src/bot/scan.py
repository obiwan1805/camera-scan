"""Scan command group — /scan start|pause|stop|progress|help."""
import asyncio
import discord
from discord import app_commands
from .common import safe_send


class ScanGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="scan", description="Camera scan controls")
        self.bot = bot

    @app_commands.command(name="help", description="Show scan command help")
    async def scan_help(self, interaction: discord.Interaction):
        embed = discord.Embed(title="/scan — Camera Scan Controls", color=0x5865F2)
        embed.add_field(
            name="/scan start",
            value="Start the Layer 1 (masscan) + Layer 2 (fingerprint) pipeline.\n"
                  "Resumes from `paused.conf` if a previous scan was paused.\n"
                  "Requires at least one target in `/target list`. "
                  "Cannot start while another scan is running.",
            inline=False,
        )
        embed.add_field(
            name="/scan pause",
            value="Pause the running scan. Waits for the pipeline to fully stop\n"
                  "before responding (masscan writes `paused.conf`).\n"
                  "Use `/scan start` to resume from where it left off.\n"
                  "Only works when a scan is running.",
            inline=False,
        )
        embed.add_field(
            name="/scan stop",
            value="Stop the scan and delete `paused.conf`. Fingerprinted results\n"
                  "are saved, but the scan will restart from scratch on next `/scan start`.\n"
                  "Only works when a scan is running.",
            inline=False,
        )
        embed.add_field(
            name="/scan progress",
            value="Show live stats: scanned IPs, discovered hosts, fingerprints,\n"
                  "queue depth, processing rate, and elapsed time.\n"
                  "Only works when a scan is running.",
            inline=False,
        )
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="start", description="Start the camera scan pipeline")
    async def scan_start(self, interaction: discord.Interaction):
        if self.bot._status == "running":
            await safe_send(interaction, content="Scan is already running.")
            return

        if self.bot._scan_task and not self.bot._scan_task.done():
            await safe_send(interaction, content="Previous scan is still shutting down, please wait...")
            return

        # Wait for old task's cleanup (gc.collect etc) to finish
        if self.bot._scan_task:
            await self.bot._scan_task

        # Check if there are targets or an imported masscan file (unless resuming)
        from pathlib import Path
        import_file = Path("data/masscan_import.txt")
        if not Path("paused.conf").exists() and not import_file.exists():
            rows = await self.bot.db.generic_list("targets")
            if not rows:
                await safe_send(interaction, content="No targets configured. Use `/target add` or `/target import-masscan` first.")
                return

        await safe_send(interaction, content="Starting scan...")

        if import_file.exists() and not Path("paused.conf").exists():
            # Feed imported masscan data directly to fingerprinter
            self.bot._scan_task = asyncio.create_task(self.bot._run_masscan_import(str(import_file)))
        else:
            self.bot._scan_task = asyncio.create_task(self.bot._run_pipeline())

    @app_commands.command(name="pause", description="Pause the current scan")
    async def scan_pause(self, interaction: discord.Interaction):
        if self.bot._status != "running":
            await safe_send(interaction, content="No scan is running.")
            return

        self.bot._status = "stopping"
        self.bot._stop_signal = True

        # Defer response — pause takes time (masscan SIGINT, pipeline teardown)
        await interaction.response.defer()

        # Wait for pipeline to fully stop
        if self.bot._scan_task:
            await self.bot._scan_task

        embed = discord.Embed(title="Scan Paused", color=0xFEE75C)
        embed.add_field(name="Status", value="Pipeline fully stopped. Use `/scan start` to resume.", inline=False)
        await interaction.followup.send(embed=embed)

    @app_commands.command(name="stop", description="Stop the current scan")
    async def scan_stop(self, interaction: discord.Interaction):
        if self.bot._status != "running":
            await safe_send(interaction, content="No scan is running.")
            return

        self.bot._status = "stopping"
        self.bot._stop_signal = True
        self.bot._delete_paused = True

        embed = self.bot._build_progress_embed()
        embed.title = "Scan Stopped"
        embed.color = 0xED4245
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="progress", description="Show current scan progress")
    async def scan_progress(self, interaction: discord.Interaction):
        if self.bot._status != "running" or (not self.bot.scanner and not self.bot.fingerprinter):
            await safe_send(interaction, content="No scan is running.")
            return

        embed = self.bot._build_progress_embed()
        await safe_send(interaction, embed=embed)
