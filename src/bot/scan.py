"""Scan command group — /scan start|pause|stop|progress."""
import asyncio
import discord
from discord import app_commands
from .common import safe_send


class ScanGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="scan", description="Camera scan controls")
        self.bot = bot

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

        await safe_send(interaction, content="Starting scan...")
        self.bot._scan_task = asyncio.create_task(self.bot._run_pipeline())

    @app_commands.command(name="pause", description="Pause the current scan")
    async def scan_pause(self, interaction: discord.Interaction):
        if self.bot._status != "running":
            await safe_send(interaction, content="No scan is running.")
            return

        self.bot._status = "stopping"
        self.bot._stop_signal = True

        embed = self.bot._build_progress_embed()
        embed.title = "Scan Paused"
        embed.color = 0xFEE75C
        await safe_send(interaction, embed=embed)

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
        if self.bot._status != "running" or not self.bot.scanner:
            await safe_send(interaction, content="No scan is running.")
            return

        embed = self.bot._build_progress_embed()
        await safe_send(interaction, embed=embed)
