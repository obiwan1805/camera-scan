"""/cve command group — CVE search results and status."""
import discord
from discord import app_commands
from .common import safe_send, PaginatedView


class CveGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="cve", description="CVE vulnerability results")
        self.bot = bot

    @app_commands.command(name="status", description="Show CVE scan results summary")
    async def cve_status(self, interaction: discord.Interaction):
        if not self.bot.storage:
            await safe_send(interaction, content="No scan data available.")
            return

        try:
            fingerprints = await self.bot.storage.read("fingerprints", {})
        except Exception:
            await safe_send(interaction, content="Error reading scan data.")
            return

        if not fingerprints:
            await safe_send(interaction, content="No fingerprints found. Run a scan first.")
            return

        # Load PoCs from bot's generic CRUD store (returns dicts)
        from src.storage.schemas import PoC
        try:
            poc_rows = await self.bot.db.generic_list("pocs")
            all_pocs = [
                PoC(
                    name=r["name"],
                    cve_id=r.get("cve_id"),
                    vendor=r.get("vendor"),
                    script_content=r.get("script_content"),
                    severity=r.get("severity"),
                    description=r.get("description"),
                )
                for r in poc_rows
            ]
        except Exception:
            all_pocs = []

        from src.layers.layer3_cve_searcher.classifier import classify_exploitability

        # Classify all targets
        counts = {"exploitable": 0, "affected": 0, "unclear": 0, "no_result": 0}

        for fp_obj in fingerprints:
            fp = fp_obj.fingerprint
            # Get PoCs matching this target's CVEs
            pocs = [p for p in all_pocs if p.cve_id and p.cve_id in fp.cves] if fp.cves else []
            status = classify_exploitability(fp, pocs)
            counts[status] += 1

        total = len(fingerprints)
        embed = discord.Embed(title="CVE Scan Results", color=0x5865F2)
        embed.add_field(
            name=":red_circle: Exploitable (has PoC)",
            value=f"{counts['exploitable']:,} targets",
            inline=True,
        )
        embed.add_field(
            name=":orange_circle: Affected (no PoC)",
            value=f"{counts['affected']:,} targets",
            inline=True,
        )
        embed.add_field(
            name=":yellow_circle: Unclear",
            value=f"{counts['unclear']:,} targets",
            inline=True,
        )
        embed.add_field(
            name=":white_circle: No Results",
            value=f"{counts['no_result']:,} targets",
            inline=True,
        )
        embed.set_footer(text=f"Total: {total:,} targets")

        await safe_send(interaction, embed=embed)

    @app_commands.command(name="list", description="List CVEs found")
    @app_commands.describe(vendor="Filter by vendor")
    async def cve_list(self, interaction: discord.Interaction, vendor: str = None):
        if not self.bot.storage:
            await safe_send(interaction, content="No scan data available.")
            return

        try:
            fingerprints = await self.bot.storage.read("fingerprints", {})
        except Exception:
            await safe_send(interaction, content="Error reading data.")
            return

        # Collect all unique CVEs from fingerprints
        from collections import defaultdict
        by_cve = defaultdict(list)  # cve_id -> list of CameraFingerprint

        for fp_obj in fingerprints:
            fp = fp_obj.fingerprint
            if not fp.cves:
                continue
            if vendor and (fp.vendor or "").lower() != vendor.lower():
                continue
            for cve_id in fp.cves:
                by_cve[cve_id].append(fp_obj)

        if not by_cve:
            await safe_send(interaction, content="No CVEs found.")
            return

        # Load PoCs for display
        try:
            poc_rows = await self.bot.db.generic_list("pocs")
            poc_by_cve = {}
            for r in poc_rows:
                cid = r.get("cve_id")
                if cid:
                    poc_by_cve[cid] = r
        except Exception:
            poc_by_cve = {}

        embeds = []
        current = discord.Embed(title="CVE List", color=0x5865F2)
        field_count = 0

        for cve_id in sorted(by_cve.keys())[:25]:
            targets = len(by_cve[cve_id])
            poc = poc_by_cve.get(cve_id)
            severity = (poc.get("severity") or "N/A") if poc else "N/A"
            msf_module = (poc.get("script_content") or "") if poc else ""
            exploitable = ":red_circle:" if msf_module else ":orange_circle:"

            current.add_field(
                name=f"{exploitable} {cve_id}",
                value=f"Severity: {severity} | Targets: {targets} | MSF: {'Yes' if msf_module else 'None'}",
                inline=False,
            )
            field_count += 1

            if field_count >= 10:
                embeds.append(current)
                current = discord.Embed(title="CVE List (continued)", color=0x5865F2)
                field_count = 0

        if field_count > 0:
            embeds.append(current)

        if len(embeds) == 1:
            await safe_send(interaction, embed=embeds[0])
        else:
            await safe_send(interaction, embed=embeds[0], view=PaginatedView(embeds))

    @app_commands.command(name="show", description="Show details for a specific CVE")
    @app_commands.describe(cve_id="CVE ID (e.g., CVE-2021-36260)")
    async def cve_show(self, interaction: discord.Interaction, cve_id: str):
        if not self.bot.storage:
            await safe_send(interaction, content="No scan data available.")
            return

        try:
            fingerprints = await self.bot.storage.read("fingerprints", {})
        except Exception:
            await safe_send(interaction, content="Error reading data.")
            return

        # Find fingerprints affected by this CVE
        affected = [fp for fp in fingerprints if cve_id in fp.fingerprint.cves]

        if not affected:
            await safe_send(interaction, content=f"No data found for {cve_id}.")
            return

        # Load matching PoC
        try:
            poc_rows = await self.bot.db.generic_list("pocs", {"cve_id": cve_id})
            poc = poc_rows[0] if poc_rows else None
        except Exception:
            poc = None

        # Get info from first affected fingerprint
        first_fp = affected[0].fingerprint
        embed = discord.Embed(title=cve_id, color=0xED4245)
        embed.add_field(
            name="Severity",
            value=(poc.get("severity") or "N/A") if poc else "N/A",
            inline=True,
        )
        embed.add_field(
            name="Vendor",
            value=first_fp.vendor or "N/A",
            inline=True,
        )
        embed.add_field(name="Affected targets", value=str(len(affected)), inline=True)

        if poc and poc.get("script_content"):
            script = poc["script_content"]
            if len(script) > 100:
                script = script[:100] + "..."
            embed.add_field(name="MSF Module", value=f"```\n{script}\n```", inline=False)
            embed.add_field(name="Status", value=":red_circle: EXPLOITABLE", inline=True)
        else:
            embed.add_field(name="Status", value=":orange_circle: AFFECTED", inline=True)

        desc = (poc.get("description") if poc else None) or first_fp.raw_banner
        if desc:
            embed.add_field(name="Description", value=desc[:500], inline=False)

        # Show affected IPs (up to 10)
        ip_list = ", ".join(fp.ip for fp in affected[:10])
        if len(affected) > 10:
            ip_list += f" ... (+{len(affected) - 10} more)"
        embed.add_field(name="Affected IPs", value=ip_list, inline=False)

        await safe_send(interaction, embed=embed)
