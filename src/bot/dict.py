"""Dict command group — /dict add|remove|import|show|list|help — password/credential dictionaries."""
import discord
from discord import app_commands
from .common import safe_send


class DictGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="dict", description="Manage password/credential dictionaries")
        self.bot = bot

    @app_commands.command(name="help", description="Show dict command help")
    async def dict_help(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="/dict — Password & Credential Dictionaries",
            description=(
                "Manage credential dictionaries for brute-force testing.\n"
                "Use any `dict_type` name. All commands work anytime."
            ),
            color=0x5865F2,
        )

        embed.add_field(
            name="Commands",
            value=(
                "`/dict list` — All dictionary types with counts\n"
                "`/dict add <dict_type> <value>` — Add single entry\n"
                "`/dict import <dict_type> <file>` — Bulk from text file\n"
                "`/dict show <dict_type>` — List entries with IDs\n"
                "`/dict remove <id>` — Delete entry by ID"
            ),
            inline=False,
        )

        embed.add_field(
            name="Common types",
            value=(
                "```\n"
                "default_usernames  admin, root, service\n"
                "default_passwords  admin123, 12345, hik12345\n"
                "default_creds      admin:admin (user:pass pairs)\n"
                "```"
            ),
            inline=False,
        )

        embed.add_field(
            name="Example",
            value=(
                "```\n"
                "/dict add default_passwords admin123\n"
                "/dict import default_creds creds.txt\n"
                "/dict show default_creds\n"
                "→ 1: admin:admin\n"
                "  2: root:toor\n"
                "  ...\n"
                "```"
            ),
            inline=False,
        )

        embed.set_footer(text="See also: /poc help")
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="add", description="Add an entry to a dictionary")
    @app_commands.describe(
        dict_type="Dictionary name (e.g. passwords, default_creds)",
        value="Entry value (e.g. admin123 or admin:admin123)"
    )
    async def dict_add(
        self, interaction: discord.Interaction,
        dict_type: str, value: str,
    ):
        storage = self.bot.db
        try:
            row_id = await storage.generic_insert("dicts", {
                "dict_type": dict_type,
                "value": value,
            })
            await safe_send(interaction, content=f"Added `{value}` to **{dict_type}** (id={row_id})")
        except Exception as e:
            await safe_send(interaction, content=f"Error: {e}")

    @app_commands.command(name="remove", description="Remove a dictionary entry by ID")
    @app_commands.describe(id="Entry ID to remove")
    async def dict_remove(self, interaction: discord.Interaction, id: int):
        storage = self.bot.db
        deleted = await storage.generic_delete("dicts", id)
        if deleted:
            await safe_send(interaction, content=f"Dict entry id={id} removed.")
        else:
            await safe_send(interaction, content=f"Dict entry id={id} not found.")

    @app_commands.command(name="import", description="Bulk import from text file (one entry per line)")
    @app_commands.describe(dict_type="Dictionary name", file="Text file: one entry per line")
    async def dict_import(
        self, interaction: discord.Interaction,
        dict_type: str, file: discord.Attachment,
    ):
        storage = self.bot.db
        try:
            raw = await file.read()
            text = raw.decode("utf-8-sig")
        except Exception as e:
            await safe_send(interaction, content=f"Failed to read file: {e}")
            return

        added = 0
        errors = 0
        for line in text.strip().split("\n"):
            entry = line.strip()
            if not entry:
                continue
            try:
                await storage.generic_insert("dicts", {
                    "dict_type": dict_type,
                    "value": entry,
                })
                added += 1
            except Exception:
                errors += 1

        msg = f"Imported **{added}** entries into **{dict_type}**"
        if errors:
            msg += f" ({errors} errors skipped)"
        await safe_send(interaction, content=msg)

    @app_commands.command(name="show", description="Show all entries in a dictionary")
    @app_commands.describe(dict_type="Dictionary name")
    async def dict_show(self, interaction: discord.Interaction, dict_type: str):
        storage = self.bot.db
        rows = await storage.generic_list("dicts", {"dict_type": dict_type})
        if not rows:
            await safe_send(interaction, content=f"No entries in **{dict_type}**.")
            return

        lines = [f"`{r['id']}` {r['value']}" for r in rows]
        text = "\n".join(lines)
        if len(text) > 1900:
            text = text[:1900] + "\n... (truncated)"
        await safe_send(interaction, content=f"**{dict_type}** ({len(rows)} entries):\n{text}")

    @app_commands.command(name="list", description="List all dictionary types and their counts")
    async def dict_list(self, interaction: discord.Interaction):
        storage = self.bot.db
        rows = await storage.generic_list("dicts")
        if not rows:
            await safe_send(interaction, content="No dictionaries yet.")
            return

        counts: dict[str, int] = {}
        for r in rows:
            t = r["dict_type"]
            counts[t] = counts.get(t, 0) + 1

        lines = [f"**{t}** — {c} entries" for t, c in sorted(counts.items())]
        await safe_send(interaction, content="\n".join(lines))
