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
        embed = discord.Embed(
            title="/scan — Camera Scan Controls",
            description=(
                "Run the two-layer pipeline:\n"
                "**Layer 1** — Masscan discovers open ports\n"
                "**Layer 2** — Fingerprinter identifies devices\n\n"
                "Pipeline: `targets → masscan → queue → fingerprinter → results`"
            ),
            color=0x5865F2,
        )

        embed.add_field(
            name="Commands",
            value=(
                "`/scan start` — Start or resume the pipeline\n"
                "`/scan pause` — Pause (resumable, writes paused.conf)\n"
                "`/scan stop` — Stop completely (deletes paused.conf)\n"
                "`/scan progress` — Live stats during a scan"
            ),
            inline=False,
        )

        embed.add_field(
            name="Typical workflow",
            value=(
                "```\n"
                "/target add 192.168.1.0/24\n"
                "/scan start\n"
                "/scan progress\n"
                "/scan pause     (or stop)\n"
                "```\n"
                "If you paused: `/scan start` resumes.\n"
                "If you stopped: `/scan start` starts fresh."
            ),
            inline=False,
        )

        embed.add_field(
            name="Requirements",
            value=(
                "- Need targets via `/target add` or `/target import`\n"
                "- Or staged masscan output via `/target import-masscan`\n"
                "- Scan must be idle to start"
            ),
            inline=False,
        )

        embed.add_field(
            name="Status states",
            value=(
                "**idle** — ready to start, config/target commands work\n"
                "**running** — only pause/stop/progress work\n"
                "**stopping** — tearing down, wait for idle"
            ),
            inline=False,
        )

        embed.set_footer(text="See also: /target help, /config help")
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
