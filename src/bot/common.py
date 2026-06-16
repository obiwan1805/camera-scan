"""Shared utilities for Discord bot command groups."""
from typing import Callable, List
import discord


async def safe_send(interaction: discord.Interaction, **kwargs):
    """Send Discord response, log errors instead of crashing."""
    try:
        if interaction.response.is_done():
            await interaction.followup.send(**kwargs)
        else:
            await interaction.response.send_message(**kwargs)
    except Exception as e:
        print(f"[Discord] Failed to respond to /{interaction.command.name}: {e}")


class PaginatedView(discord.ui.View):
    """Paginated embed with prev/next buttons."""

    def __init__(self, embeds: List[discord.Embed], timeout: int = 120):
        super().__init__(timeout=timeout)
        self.embeds = embeds
        self.page = 0

    @discord.ui.button(label="Prev", style=discord.ButtonStyle.secondary, row=0)
    async def prev(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.page > 0:
            self.page -= 1
        await interaction.response.edit_message(embed=self.embeds[self.page], view=self)

    @discord.ui.button(label="Next", style=discord.ButtonStyle.secondary, row=0)
    async def next(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.page < len(self.embeds) - 1:
            self.page += 1
        await interaction.response.edit_message(embed=self.embeds[self.page], view=self)


class ConfirmView(discord.ui.View):
    """Confirm or cancel an action."""

    def __init__(self, confirm_fn: Callable, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._confirm_fn = confirm_fn
        self.confirmed = False

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger, row=0)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.confirmed = True
        self.stop()
        await self._confirm_fn(interaction)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, row=0)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content="Cancelled.", view=None)


async def global_help(interaction: discord.Interaction):
    """Global /help — shows all command groups and a quick-start guide."""
    embed = discord.Embed(
        title="Camera Scan Bot — Help",
        description=(
            "Discovers IP cameras, fingerprints them, and assesses vulnerabilities.\n\n"
            "**Pipeline:** `targets → masscan → fingerprinter → results`"
        ),
        color=0x57F287,
    )

    embed.add_field(
        name="Quick start",
        value=(
            "```\n"
            "/target add 192.168.1.0/24\n"
            "/scan start\n"
            "/scan progress\n"
            "```"
        ),
        inline=False,
    )

    embed.add_field(
        name="Command groups",
        value=(
            "**`/scan`** — Start, pause, stop, check progress\n"
            "**`/target`** — Add/import IPs, CIDRs, ranges\n"
            "**`/config`** — Tune scan rate, timeouts, concurrency\n"
            "**`/signature`** — Manage fingerprint patterns\n"
            "**`/poc`** — Store proof-of-concept scripts\n"
            "**`/dict`** — Password/credential dictionaries"
        ),
        inline=False,
    )

    embed.add_field(
        name="Getting help",
        value=(
            "Every group has detailed help:\n"
            "`/scan help`  `/target help`  `/config help`\n"
            "`/signature help`  `/poc help`  `/dict help`"
        ),
        inline=False,
    )

    embed.add_field(
        name="Two scan modes",
        value=(
            "**CIDR mode** — `/target add` then `/scan start`\n"
            "Runs masscan + fingerprinter.\n\n"
            "**Import mode** — `/target import-masscan` then `/scan start`\n"
            "Fingerprinter only (no masscan, no root)."
        ),
        inline=False,
    )

    embed.set_footer(text="Type any /<group> help for detailed usage and examples")
    await interaction.response.send_message(embed=embed)

