"""Target command group — manage scan inputs (IPs, CIDRs, ranges)."""
import asyncio
import io
import ipaddress
import discord
from discord import app_commands
from pathlib import Path
from .common import safe_send, ConfirmView, PaginatedView

from src.utils.network import classify_target, count_ips_in_cidr, count_ips_in_range
from src.layers import PortScanner


class ClearTargetsView(discord.ui.View):
    """Two-button view: export then delete, or just delete."""

    def __init__(self, bot: 'ScanBot', timeout: int = 60):
        super().__init__(timeout=timeout)
        self.bot = bot

    async def _execute_clear(self, interaction: discord.Interaction, export: bool):
        await interaction.response.defer()

        storage = self.bot.db
        files: list[discord.File] = []
        export_summary = ""

        if export:
            try:
                l1_csv, l1_count = await storage.dump_table_csv("port_scans")
                l2_csv, l2_count = await storage.dump_table_csv("fingerprints")
                if l1_count > 0:
                    files.append(discord.File(io.BytesIO(l1_csv.encode()), filename="layer1_port_scans.csv"))
                if l2_count > 0:
                    files.append(discord.File(io.BytesIO(l2_csv.encode()), filename="layer2_fingerprints.csv"))
                export_summary = f" Exported {l1_count} layer-1 + {l2_count} layer-2 rows."
            except Exception as e:
                await interaction.followup.send(f"Export failed: {e}")
                return

        target_rows = await storage.generic_list("targets")
        for r in target_rows:
            await storage.generic_delete("targets", r["id"])

        results_counts = await storage.clear_results()

        paused = Path("paused.conf")
        if paused.exists():
            paused.unlink()

        scans_dir = Path("data/scans")
        deleted_files = 0
        if scans_dir.exists():
            for f in scans_dir.glob("results_*.txt"):
                try:
                    f.unlink()
                    deleted_files += 1
                except Exception:
                    pass

        total_results = sum(results_counts.values())
        msg = (
            f"Cleared **{len(target_rows)}** targets, **{total_results}** result rows, "
            f"**{deleted_files}** masscan files.{export_summary}"
        )
        await interaction.followup.send(content=msg, files=files or None)

    @discord.ui.button(label="Export then delete", style=discord.ButtonStyle.success, row=0)
    async def export_then_delete(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await self._execute_clear(interaction, export=True)

    @discord.ui.button(label="Just delete", style=discord.ButtonStyle.danger, row=0)
    async def just_delete(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await self._execute_clear(interaction, export=False)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, row=1)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content="Cancelled.", embed=None, view=None)


class TargetGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="target", description="Manage scan inputs (IPs, CIDRs)")
        self.bot = bot

    def _check_idle(self, interaction: discord.Interaction) -> bool:
        if self.bot._status != "idle":
            return False
        return True

    @app_commands.command(name="help", description="Show target command help")
    async def target_help(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="/target — Scan Input Management",
            description=(
                "Manage what gets scanned. Two input modes:\n"
                "**CIDR mode** — Add IPs/ranges/CIDRs → masscan sweeps them\n"
                "**Import mode** — Stage masscan output → fingerprinter only"
            ),
            color=0x5865F2,
        )

        embed.add_field(
            name="Commands",
            value=(
                "`/target add <target>` — Add IP, CIDR, or range\n"
                "`/target remove <id>` — Remove by ID\n"
                "`/target list [type]` — List all (works during scan)\n"
                "`/target import <file>` — Bulk import from text file\n"
                "`/target export` — Export to data/cidrs.txt\n"
                "`/target clear` — Remove all (with confirmation)\n"
                "`/target import-masscan <file>` — Stage masscan -oL output"
            ),
            inline=False,
        )

        embed.add_field(
            name="Target formats",
            value=(
                "```\n"
                "192.168.1.0/24        ← CIDR (256 IPs)\n"
                "10.0.0.1              ← single IP\n"
                "1.0.0.0-1.0.255.255   ← IP range (65536 IPs)\n"
                "```"
            ),
            inline=False,
        )

        embed.add_field(
            name="Example: CIDR scan",
            value=(
                "```\n"
                "/target add 192.168.1.0/24\n"
                "→ Added 192.168.1.0/24 (cidr) — 256 IPs\n"
                "\n/scan start\n"
                "```"
            ),
            inline=False,
        )

        embed.add_field(
            name="Example: Masscan import",
            value=(
                "```\n"
                "/target import-masscan results.txt\n"
                "→ Imported 5,000 hosts, 8,000 entries\n"
                "\n/scan start\n"
                "→ Runs Layer 2 only (no masscan)\n"
                "```\n"
                "File format: `open tcp <port> <ip> <timestamp>`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Rules",
            value=(
                "- `list` and `export` work anytime\n"
                "- All other commands require scan to be idle\n"
                "- `clear` also deletes paused.conf"
            ),
            inline=False,
        )

        embed.set_footer(text="See also: /scan help, /config help")
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="add", description="Add a scan target (IP, CIDR, or range)")
    @app_commands.describe(target="IP, CIDR, or IP range (e.g. 192.168.1.0/24)")
    async def target_add(self, interaction: discord.Interaction, target: str):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Scan is running. Pause or stop first.")
            return

        target = target.strip()
        target_type = classify_target(target)

        if target_type == "cidr":
            try:
                ipaddress.ip_network(target, strict=False)
            except ValueError:
                await safe_send(interaction, content=f"Invalid CIDR: `{target}`")
                return
        elif target_type == "ip":
            try:
                ipaddress.ip_address(target)
            except ValueError:
                await safe_send(interaction, content=f"Invalid IP: `{target}`")
                return
        elif target_type == "range":
            parts = target.split("-")
            if len(parts) != 2:
                await safe_send(interaction, content=f"Invalid range: `{target}`")
                return
            try:
                ipaddress.ip_address(parts[0].strip())
                ipaddress.ip_address(parts[1].strip())
            except ValueError:
                await safe_send(interaction, content=f"Invalid range: `{target}`")
                return

        storage = self.bot.db
        try:
            row_id = await storage.generic_insert("targets", {
                "target": target,
                "type": target_type,
            })
            rows = await storage.generic_list("targets")
            total_ips = sum(
                count_ips_in_cidr(r["target"]) if r["type"] != "range"
                else count_ips_in_range(r["target"])
                for r in rows
            )
            await safe_send(
                interaction,
                content=f"Added **{target}** ({target_type}) — id={row_id}, total={len(rows)} targets, {total_ips:,} IPs",
            )
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                await safe_send(interaction, content=f"Target **{target}** already exists.")
            else:
                await safe_send(interaction, content=f"Error: {e}")

    @app_commands.command(name="remove", description="Remove a target by ID")
    @app_commands.describe(id="Target ID to remove")
    async def target_remove(self, interaction: discord.Interaction, id: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Scan is running. Pause or stop first.")
            return

        storage = self.bot.db
        deleted = await storage.generic_delete("targets", id)
        if deleted:
            await safe_send(interaction, content=f"Target id={id} removed.")
        else:
            await safe_send(interaction, content=f"Target id={id} not found.")

    @app_commands.command(name="list", description="List all scan targets")
    @app_commands.describe(type="Filter by type: cidr, ip, range")
    async def target_list(self, interaction: discord.Interaction, type: str = ""):
        storage = self.bot.db

        filters = {"type": type} if type else None
        rows = await storage.generic_list("targets", filters)

        if not rows:
            await safe_send(interaction, content="No targets configured.")
            return

        total_ips = 0
        entries = []
        for r in rows:
            t_type = r["type"]
            if t_type == "range":
                count = count_ips_in_range(r["target"])
            else:
                count = count_ips_in_cidr(r["target"])
            total_ips += count
            entries.append(f"`{r['id']}` **{r['target']}** ({t_type}, {count:,} IPs)")

        per_page = 15
        embeds = []
        for i in range(0, len(entries), per_page):
            chunk = entries[i:i + per_page]
            page_num = i // per_page + 1
            total_pages = (len(entries) + per_page - 1) // per_page
            embed = discord.Embed(
                title=f"Scan Targets (page {page_num}/{total_pages})",
                color=0x5865F2,
            )
            embed.description = "\n".join(chunk)
            embed.set_footer(text=f"{len(rows)} targets, {total_ips:,} IPs total")
            embeds.append(embed)

        if len(embeds) == 1:
            await safe_send(interaction, embed=embeds[0])
        else:
            await safe_send(interaction, embed=embeds[0], view=PaginatedView(embeds))

    @app_commands.command(name="import", description="Bulk import targets from file")
    @app_commands.describe(file="Text file with one IP/CIDR/range per line")
    async def target_import(self, interaction: discord.Interaction, file: discord.Attachment):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Scan is running. Pause or stop first.")
            return

        try:
            raw = await file.read()
            text = raw.decode("utf-8-sig")
        except Exception as e:
            await safe_send(interaction, content=f"Failed to read file: {e}")
            return

        storage = self.bot.db
        added = 0
        errors = 0
        total_ips = 0
        for line in text.strip().split("\n"):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            target_type = classify_target(entry)
            try:
                await storage.generic_insert("targets", {
                    "target": entry,
                    "type": target_type,
                })
                added += 1
                if target_type == "range":
                    total_ips += count_ips_in_range(entry)
                else:
                    total_ips += count_ips_in_cidr(entry)
            except Exception:
                errors += 1

        msg = f"Imported **{added}** targets ({total_ips:,} IPs)"
        if errors:
            msg += f" ({errors} duplicates/errors skipped)"
        await safe_send(interaction, content=msg)

    @app_commands.command(name="clear", description="Remove ALL targets, scan results, and masscan files")
    async def target_clear(self, interaction: discord.Interaction):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Scan is running. Pause or stop first.")
            return

        embed = discord.Embed(
            title="Clear all scan data?",
            description=(
                "This wipes **everything** for a fresh campaign:\n"
                "- `targets` table\n"
                "- `port_scans` (Layer 1 results)\n"
                "- `fingerprints` (Layer 2 results)\n"
                "- `raw_responses`\n"
                "- `paused.conf`\n"
                "- `data/scans/results_*.txt` files\n\n"
                "**Export then delete** — attach CSVs of Layer 1 + Layer 2 first.\n"
                "**Just delete** — wipe immediately, no export."
            ),
            color=0xED4245,
        )
        view = ClearTargetsView(self.bot)
        await safe_send(interaction, embed=embed, view=view)

    @app_commands.command(name="export", description="Export targets to data/cidrs.txt")
    async def target_export(self, interaction: discord.Interaction):
        storage = self.bot.db
        rows = await storage.generic_list("targets")
        if not rows:
            await safe_send(interaction, content="No targets to export.")
            return
        content = "\n".join(r["target"] for r in rows) + "\n"
        Path("data/cidrs.txt").write_text(content)
        total_ips = sum(
            count_ips_in_cidr(r["target"]) if r["type"] != "range"
            else count_ips_in_range(r["target"])
            for r in rows
        )
        await safe_send(
            interaction,
            content=f"Exported {len(rows)} targets ({total_ips:,} IPs) to `data/cidrs.txt`",
        )

    @app_commands.command(name="import-masscan", description="Import masscan -oL output into fingerprinter")
    @app_commands.describe(file="Masscan -oL output file")
    async def target_import_masscan(self, interaction: discord.Interaction, file: discord.Attachment):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Scan is running. Stop first.")
            return

        try:
            raw = await file.read()
        except Exception as e:
            await safe_send(interaction, content=f"Failed to read file: {e}")
            return

        # Save raw masscan output — /scan start will feed it like live masscan
        Path("data").mkdir(exist_ok=True)
        Path("data/masscan_import.txt").write_bytes(raw)

        # Quick count for summary
        text = raw.decode("utf-8-sig", errors="ignore")
        hosts = set()
        count = 0
        for line in text.splitlines():
            result = PortScanner.parse_masscan_line(line)
            if result:
                hosts.add(result[0])
                count += 1

        if count == 0:
            Path("data/masscan_import.txt").unlink()
            await safe_send(interaction, content="No valid entries found in file.")
            return
        await safe_send(
            interaction,
            content=f"Imported **{len(hosts):,}** hosts, **{count:,}** entries.\n"
                    f"Use `/scan start` to begin fingerprinting.",
        )
