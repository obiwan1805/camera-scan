"""Target command group — /target add|remove|list|show|help."""
import json
import discord
from discord import app_commands
from .common import safe_send


class TargetGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="target", description="Manage camera/NVR targets")
        self.bot = bot

    @app_commands.command(name="help", description="Show target command help")
    async def target_help(self, interaction: discord.Interaction):
        embed = discord.Embed(title="/target — Camera & NVR Target Management", color=0x5865F2)
        embed.add_field(
            name="/target list `[vendor]`",
            value="List all targets. Optionally filter by vendor.\n"
                  "Shows ID, name, aliases, vendor, and category.",
            inline=False,
        )
        embed.add_field(
            name="/target add `<name>` `[options]`",
            value="Add a new target. Required: `name`. Options: `vendor`,\n"
                  "`category` (ip_camera/nvr/dvr/router), `aliases` (comma-separated).",
            inline=False,
        )
        embed.add_field(
            name="/target show `<id>`",
            value="Show full target details: vendor, category, and aliases.",
            inline=False,
        )
        embed.add_field(
            name="/target remove `<id>`",
            value="Remove a target by its ID.",
            inline=False,
        )
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="add", description="Add a new target")
    @app_commands.describe(
        name="Target name (e.g. DS-2CD2142FWD)", vendor="Vendor name",
        category="ip_camera, nvr, dvr, router", aliases="Comma-separated aliases"
    )
    async def target_add(
        self, interaction: discord.Interaction, name: str,
        vendor: str = "", category: str = "", aliases: str = "",
    ):
        storage = self.bot.db

        alias_list = [a.strip() for a in aliases.split(",") if a.strip()] if aliases else []
        data = {
            "name": name,
            "aliases": json.dumps(alias_list),
            "vendor": vendor or None,
            "category": category or None,
            "metadata": "{}",
        }
        try:
            row_id = await storage.generic_insert("targets", data)
            await safe_send(interaction, content=f"Target **{name}** added (id={row_id})")
        except Exception as e:
            await safe_send(interaction, content=f"Error: {e}")

    @app_commands.command(name="remove", description="Remove a target by ID")
    @app_commands.describe(id="Target ID to remove")
    async def target_remove(self, interaction: discord.Interaction, id: int):
        storage = self.bot.db

        deleted = await storage.generic_delete("targets", id)
        if deleted:
            await safe_send(interaction, content=f"Target id={id} removed.")
        else:
            await safe_send(interaction, content=f"Target id={id} not found.")

    @app_commands.command(name="list", description="List all targets")
    @app_commands.describe(vendor="Filter by vendor")
    async def target_list(self, interaction: discord.Interaction, vendor: str = ""):
        storage = self.bot.db

        filters = {"vendor": vendor} if vendor else None
        rows = await storage.generic_list("targets", filters)

        if not rows:
            await safe_send(interaction, content="No targets found.")
            return

        lines = []
        for r in rows:
            alias_str = ""
            aliases = r.get('aliases', '[]')
            if isinstance(aliases, str):
                aliases = json.loads(aliases)
            if aliases:
                alias_str = f" ({', '.join(aliases)})"
            line = f"`{r['id']}` **{r['name']}**{alias_str} — {r.get('vendor') or '?'} | {r.get('category') or '?'}"
            lines.append(line)

        text = "\n".join(lines)
        if len(text) > 1900:
            text = text[:1900] + "\n... (truncated)"
        await safe_send(interaction, content=text)

    @app_commands.command(name="show", description="Show full target details by ID")
    @app_commands.describe(id="Target ID")
    async def target_show(self, interaction: discord.Interaction, id: int):
        storage = self.bot.db

        row = await storage.generic_get("targets", id)
        if not row:
            await safe_send(interaction, content=f"Target id={id} not found.")
            return

        embed = discord.Embed(
            title=f"Target: {row['name']}", color=0x57F287
        )
        embed.add_field(name="Vendor", value=row.get('vendor') or "N/A", inline=True)
        embed.add_field(name="Category", value=row.get('category') or "N/A", inline=True)

        aliases = row.get('aliases', '[]')
        if isinstance(aliases, str):
            aliases = json.loads(aliases)
        embed.add_field(name="Aliases", value=", ".join(aliases) or "None", inline=False)

        await safe_send(interaction, embed=embed)
