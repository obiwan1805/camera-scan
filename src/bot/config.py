"""Config command group — /config show|scan_rate|max_concurrent|batch_size|help."""
import discord
from discord import app_commands
from .common import safe_send


class ConfigGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="config", description="Configure scan parameters")
        self.bot = bot

    @app_commands.command(name="help", description="Show config command help")
    async def config_help(self, interaction: discord.Interaction):
        embed = discord.Embed(title="/config — Scan Configuration", color=0x5865F2)
        embed.add_field(
            name="/config show",
            value="Display all current config values including masscan rate,\n"
                  "max concurrent tasks, and batch size.",
            inline=False,
        )
        embed.add_field(
            name="/config scan_rate `<value>`",
            value="Set masscan packets-per-second rate. Higher = faster but noisier.\n"
                  "Default: 10,000. Cannot change while a scan is running.",
            inline=False,
        )
        embed.add_field(
            name="/config max_concurrent `<value>`",
            value="Max concurrent fingerprinter tasks. Controls how many IPs are\n"
                  "probed simultaneously. Default: 200. Cannot change while running.",
            inline=False,
        )
        embed.add_field(
            name="/config batch_size `<value>`",
            value="Number of IPs passed from Layer 1 to Layer 2 per batch.\n"
                  "Default: 1000. Cannot change while a scan is running.",
            inline=False,
        )
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="show", description="Show current config values")
    async def config_show(self, interaction: discord.Interaction):
        embed = self.bot._build_config_embed()
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="scan_rate", description="Set masscan rate (packets/sec)")
    @app_commands.describe(value="Masscan rate in packets/sec")
    async def config_scan_rate(self, interaction: discord.Interaction, value: int):
        if self.bot._status != "idle":
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["scan_rate"] = value
        await safe_send(interaction, content=f"scan_rate set to {value:,} pps")

    @app_commands.command(name="max_concurrent", description="Set max concurrent fingerprinter tasks")
    @app_commands.describe(value="Max concurrent tasks")
    async def config_max_concurrent(self, interaction: discord.Interaction, value: int):
        if self.bot._status != "idle":
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["max_concurrent"] = value
        await safe_send(interaction, content=f"max_concurrent set to {value}")

    @app_commands.command(name="batch_size", description="Set scanner batch size")
    @app_commands.describe(value="Batch size")
    async def config_batch_size(self, interaction: discord.Interaction, value: int):
        if self.bot._status != "idle":
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["batch_size"] = value
        await safe_send(interaction, content=f"batch_size set to {value}")
