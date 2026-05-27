"""PoC command group — /poc add|remove|list|show."""
import json
import discord
from discord import app_commands
from .common import safe_send


class PoCGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="poc", description="Manage PoC scripts")
        self.bot = bot

    @app_commands.command(name="add", description="Add a new PoC script")
    @app_commands.describe(
        name="Script name", cve_id="CVE identifier", vendor="Target vendor",
        protocol="http, rtsp, onvif, etc.", script_type="python, bash, powershell",
        description="What it does", severity="critical, high, medium, low",
        file="Upload script file", script_content="Or paste script code here"
    )
    async def poc_add(
        self, interaction: discord.Interaction, name: str,
        cve_id: str = "", vendor: str = "", protocol: str = "",
        script_type: str = "python", description: str = "", severity: str = "",
        file: discord.Attachment = None, script_content: str = "",
    ):
        storage = self.bot.db

        # Read script from file upload or text input
        if file:
            try:
                raw = await file.read()
                script = raw.decode("utf-8")
            except Exception as e:
                await safe_send(interaction, content=f"Failed to read file: {e}")
                return
        elif script_content:
            script = script_content
        else:
            await safe_send(interaction, content="Provide either a file upload or script_content.")
            return

        data = {
            "name": name,
            "cve_id": cve_id or None,
            "vendor": vendor or None,
            "target_names": "[]",
            "protocol": protocol or None,
            "script_type": script_type or None,
            "script_content": script,
            "description": description or None,
            "severity": severity or None,
            "enabled": 1,
        }
        try:
            row_id = await storage.generic_insert("pocs", data)
            await safe_send(interaction, content=f"PoC **{name}** added (id={row_id})")
        except Exception as e:
            await safe_send(interaction, content=f"Error: {e}")

    @app_commands.command(name="remove", description="Remove a PoC script by ID")
    @app_commands.describe(id="PoC ID to remove")
    async def poc_remove(self, interaction: discord.Interaction, id: int):
        storage = self.bot.db

        deleted = await storage.generic_delete("pocs", id)
        if deleted:
            await safe_send(interaction, content=f"PoC id={id} removed.")
        else:
            await safe_send(interaction, content=f"PoC id={id} not found.")

    @app_commands.command(name="list", description="List all PoCs")
    @app_commands.describe(vendor="Filter by vendor")
    async def poc_list(self, interaction: discord.Interaction, vendor: str = ""):
        storage = self.bot.db

        filters = {"vendor": vendor} if vendor else None
        rows = await storage.generic_list("pocs", filters)

        if not rows:
            await safe_send(interaction, content="No PoCs found.")
            return

        lines = []
        for r in rows:
            line = f"`{r['id']}` **{r['name']}** — {r.get('cve_id') or 'no CVE'} | {r.get('vendor') or '?'} | {r.get('severity') or '?'}"
            lines.append(line)

        text = "\n".join(lines)
        if len(text) > 1900:
            text = text[:1900] + "\n... (truncated)"
        await safe_send(interaction, content=text)

    @app_commands.command(name="show", description="Show full PoC details by ID")
    @app_commands.describe(id="PoC ID")
    async def poc_show(self, interaction: discord.Interaction, id: int):
        storage = self.bot.db

        row = await storage.generic_get("pocs", id)
        if not row:
            await safe_send(interaction, content=f"PoC id={id} not found.")
            return

        embed = discord.Embed(
            title=f"PoC: {row['name']}", color=0x5865F2,
            description=row.get('description') or "No description"
        )
        embed.add_field(name="CVE", value=row.get('cve_id') or "N/A", inline=True)
        embed.add_field(name="Vendor", value=row.get('vendor') or "N/A", inline=True)
        embed.add_field(name="Protocol", value=row.get('protocol') or "N/A", inline=True)
        embed.add_field(name="Type", value=row.get('script_type') or "N/A", inline=True)
        embed.add_field(name="Severity", value=row.get('severity') or "N/A", inline=True)
        embed.add_field(name="Enabled", value=str(row.get('enabled', 1)), inline=True)

        targets = row.get('target_names', '[]')
        if isinstance(targets, str):
            targets = json.loads(targets)
        embed.add_field(name="Targets", value=", ".join(targets) or "None", inline=False)

        script = row.get('script_content') or ''
        if len(script) > 1000:
            script = script[:1000] + "\n... (truncated)"
        embed.add_field(name="Script", value=f"```\n{script}\n```", inline=False)

        await safe_send(interaction, embed=embed)
