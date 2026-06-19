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

        # Re-check idle at button-click time — user may have started a scan
        # in another channel between showing this view and clicking.
        if self.bot._status != "idle":
            await interaction.followup.send(
                content="Scan is no longer idle. Stop the scan first, then re-run `/target clear`."
            )
            return

        storage = self.bot.db
        files: list[discord.File] = []
        export_summary = ""
        errors: list[str] = []

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

        try:
            target_rows = await storage.generic_list("targets")
            for r in target_rows:
                await storage.generic_delete("targets", r["id"])
        except Exception as e:
            errors.append(f"targets: {e}")

        try:
            results_counts = await storage.clear_results()
        except Exception as e:
            errors.append(f"results: {e}")
            results_counts = {}

        try:
            paused = Path("paused.conf")
            if paused.exists():
                paused.unlink()
        except Exception as e:
            errors.append(f"paused.conf: {e}")

        deleted_files = 0
        try:
            scans_dir = Path("data/scans")
            if scans_dir.exists():
                for f in scans_dir.glob("results_*.txt"):
                    try:
                        f.unlink()
                        deleted_files += 1
                    except Exception:
                        pass
        except Exception as e:
            errors.append(f"scan files: {e}")

        total_results = sum(results_counts.values()) if results_counts else 0
        msg = (
            f"Cleared **{len(target_rows) if 'target_rows' in locals() else 0}** targets, "
            f"**{total_results}** result rows, **{deleted_files}** masscan files.{export_summary}"
        )
        if errors:
            msg += f"\n⚠️ Partial failures: {' | '.join(errors)}"
        try:
            await interaction.followup.send(content=msg, files=files or None)
        except Exception as e:
            print(f"[ClearTargetsView] followup failed: {e}")

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

    async def on_timeout(self):
        # Disable buttons so the user can see the view has expired
        for child in self.children:
            child.disabled = True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item):
        print(f"[ClearTargetsView error] {type(error).__name__}: {error}")
        try:
            if interaction.response.is_done():
                await interaction.followup.send(f"Operation failed: {error}", ephemeral=True)
            else:
                await interaction.response.send_message(f"Operation failed: {error}", ephemeral=True)
        except Exception:
            pass


class RemoveTargetView(discord.ui.View):
    """Three-button view for /target remove: cascade delete, target only, or cancel."""

    def __init__(self, bot: 'ScanBot', target_id: int, target_spec: str,
                 target_type: str, ip_count: int, impact: dict[str, int],
                 timeout: int = 60):
        super().__init__(timeout=timeout)
        self.bot = bot
        self.target_id = target_id
        self.target_spec = target_spec
        self.target_type = target_type
        self.ip_count = ip_count
        self.impact = impact

    async def _execute_remove(self, interaction: discord.Interaction, cascade: bool):
        await interaction.response.defer()

        if self.bot._status != "idle":
            await interaction.followup.send(
                content="Scan is no longer idle. Stop the scan first, then re-run `/target remove`."
            )
            return

        storage = self.bot.db
        errors: list[str] = []
        cascade_summary = ""

        try:
            deleted_target = await storage.generic_delete("targets", self.target_id)
        except Exception as e:
            errors.append(f"target: {e}")
            deleted_target = False

        if not deleted_target and not errors:
            await interaction.followup.send(content=f"Target id={self.target_id} not found.")
            return

        if cascade:
            try:
                counts = await storage.clear_target_results(self.target_spec)
                total = sum(counts.values())
                cascade_summary = (
                    f" Also deleted **{total}** result rows "
                    f"({counts.get('port_scans', 0)} port scans, "
                    f"{counts.get('fingerprints', 0)} fingerprints, "
                    f"{counts.get('raw_responses', 0)} raw responses, "
                    f"{counts.get('claims', 0)} claims)."
                )
            except Exception as e:
                errors.append(f"cascade: {e}")

        msg = f"Target id={self.target_id} (**{self.target_spec}**) removed.{cascade_summary}"
        if errors:
            msg += f"\n⚠️ Partial failures: {' | '.join(errors)}"
        try:
            await interaction.followup.send(content=msg)
        except Exception as e:
            print(f"[RemoveTargetView] followup failed: {e}")

    @discord.ui.button(label="Remove all (cascade)", style=discord.ButtonStyle.danger, row=0)
    async def remove_all(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await self._execute_remove(interaction, cascade=True)

    @discord.ui.button(label="Target only", style=discord.ButtonStyle.secondary, row=0)
    async def target_only(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await self._execute_remove(interaction, cascade=False)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, row=1)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content="Cancelled.", embed=None, view=None)

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True

    async def on_error(self, interaction: discord.Interaction, error: Exception, item):
        print(f"[RemoveTargetView error] {type(error).__name__}: {error}")
        try:
            if interaction.response.is_done():
                await interaction.followup.send(f"Operation failed: {error}", ephemeral=True)
            else:
                await interaction.response.send_message(f"Operation failed: {error}", ephemeral=True)
        except Exception:
            pass


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

        # Look up the target row to compute impact
        target_row = None
        try:
            rows = await storage.generic_list("targets")
            for r in rows:
                if r["id"] == id:
                    target_row = r
                    break
        except Exception as e:
            await safe_send(interaction, content=f"Failed to look up target: {e}")
            return

        if not target_row:
            await safe_send(interaction, content=f"Target id={id} not found.")
            return

        target_spec = target_row["target"]
        target_type = target_row["type"]
        if target_type == "range":
            ip_count = count_ips_in_range(target_spec)
        else:
            ip_count = count_ips_in_cidr(target_spec)

        # Pre-count related result rows for the confirmation embed
        try:
            impact = await storage.count_target_results(target_spec)
        except Exception as e:
            await safe_send(interaction, content=f"Failed to count related results: {e}")
            return

        total_results = sum(impact.values())
        embed = discord.Embed(
            title=f"Remove target id={id}?",
            description=(
                f"**{target_spec}** ({target_type}, {ip_count:,} IPs)\n\n"
                f"Related rows that would also be deleted on cascade:\n"
                f"- port_scans: **{impact.get('port_scans', 0):,}**\n"
                f"- fingerprints: **{impact.get('fingerprints', 0):,}**\n"
                f"- raw_responses: **{impact.get('raw_responses', 0):,}**\n"
                f"- claims: **{impact.get('claims', 0):,}**\n\n"
                f"**Remove all** — delete target + the {total_results:,} rows above.\n"
                f"**Target only** — delete target, keep result rows."
            ),
            color=0xED4245,
        )
        view = RemoveTargetView(
            bot=self.bot,
            target_id=id,
            target_spec=target_spec,
            target_type=target_type,
            ip_count=ip_count,
            impact=impact,
        )
        await safe_send(interaction, embed=embed, view=view)

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

        # Defer before slow file I/O + per-line DB inserts
        await interaction.response.defer()

        try:
            raw = await file.read()
            text = raw.decode("utf-8-sig")
        except Exception as e:
            await interaction.followup.send(content=f"Failed to read file: {e}")
            return

        storage = self.bot.db
        added = 0
        errors = 0
        total_ips = 0
        try:
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
        except Exception as e:
            await interaction.followup.send(content=f"Import aborted: {e}")
            return

        msg = f"Imported **{added}** targets ({total_ips:,} IPs)"
        if errors:
            msg += f" ({errors} duplicates/errors skipped)"
        await interaction.followup.send(content=msg)

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

        # Defer before slow file read + parse
        await interaction.response.defer()

        try:
            raw = await file.read()
        except Exception as e:
            await interaction.followup.send(content=f"Failed to read file: {e}")
            return

        try:
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
                await interaction.followup.send(content="No valid entries found in file.")
                return
            await interaction.followup.send(
                content=f"Imported **{len(hosts):,}** hosts, **{count:,}** entries.\n"
                        f"Use `/scan start` to begin fingerprinting.",
            )
        except Exception as e:
            await interaction.followup.send(content=f"Import failed: {e}")
