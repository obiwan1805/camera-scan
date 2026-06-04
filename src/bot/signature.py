"""Signature command group with rich Discord UI."""
import io
import re
import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional, List, Callable
from .common import safe_send, ConfirmView, PaginatedView

from src.layers.layer2_fingerprinter.signatures.loader import SignatureLoader
from src.layers.layer2_fingerprinter.engine import SignatureEngine
from src.layers.layer2_fingerprinter.probers import HTTPProber, HTTPSProber, RTSPProber


# ---------------------------------------------------------------------------
# Views (interactive components)
# ---------------------------------------------------------------------------


class VendorSelect(discord.ui.Select):
    """Dropdown to pick a vendor from loaded signatures."""

    def __init__(self, loader: SignatureLoader, callback_fn: Callable):
        options = [
            discord.SelectOption(label=sig.vendor, value=sig.vendor)
            for sig in loader.signatures
        ][:25]
        super().__init__(placeholder="Select vendor...", options=options)
        self._callback = callback_fn

    async def callback(self, interaction: discord.Interaction):
        await self._callback(interaction, self.values[0])



# ---------------------------------------------------------------------------
# Modals (popup forms)
# ---------------------------------------------------------------------------

class TestSignatureModal(discord.ui.Modal, title="Test Signature Regex"):
    """Test a regex pattern against sample text."""

    pattern = discord.ui.TextInput(
        label="Pattern / Regex",
        placeholder=r"e.g. IPC-HFW\d+[A-Za-z\d-]*",
        required=True, style=discord.TextStyle.paragraph,
    )
    sample = discord.ui.TextInput(
        label="Sample text",
        placeholder="Paste HTML, XML, or any text to test against",
        required=True, style=discord.TextStyle.paragraph,
    )

    def __init__(self, group: 'SignatureGroup'):
        super().__init__()
        self._group = group

    async def on_submit(self, interaction: discord.Interaction):
        pattern = self.pattern.value.strip()
        sample = self.sample.value

        try:
            flags = re.DOTALL | re.IGNORECASE
            m = re.search(pattern, sample, flags)

            if m:
                lines = [f"**Match found**"]
                lines.append(f"Pattern: `{pattern}`")
                lines.append(f"Match: `{m.group(0)}`")
                for i, g in enumerate(m.groups(), 1):
                    if g is not None:
                        lines.append(f"Group {i}: `{g}`")

                view = _TestResultView(self._group, pattern)
                await safe_send(interaction, content="\n".join(lines), view=view)
            else:
                view = _RetryTestView(self._group, pattern)
                await safe_send(interaction, content=f"**No match** for `{pattern}`", view=view)
        except re.error as e:
            await safe_send(interaction, content=f"**Invalid regex:** {e}")


class _TestResultView(discord.ui.View):
    """Shown after a successful test — Add button or Test Again."""

    def __init__(self, group: 'SignatureGroup', pattern: str):
        super().__init__(timeout=60)
        self._group = group
        self._pattern = pattern

    @discord.ui.button(label="Add to Signature", style=discord.ButtonStyle.success, row=0)
    async def add_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = AddSignatureModal(self._group, pattern_default=self._pattern)
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Test Again", style=discord.ButtonStyle.secondary, row=0)
    async def retry_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TestSignatureModal(self._group)
        modal.pattern.default = self._pattern
        await interaction.response.send_modal(modal)


class _RetryTestView(discord.ui.View):
    """Shown after a failed test — re-opens test modal with pattern kept."""

    def __init__(self, group: 'SignatureGroup', pattern: str):
        super().__init__(timeout=60)
        self._group = group
        self._pattern = pattern

    @discord.ui.button(label="Edit & Retry", style=discord.ButtonStyle.primary, row=0)
    async def retry_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TestSignatureModal(self._group)
        modal.pattern.default = self._pattern
        await interaction.response.send_modal(modal)


class _AddPreviewView(discord.ui.View):
    """Preview after add modal — Test or Confirm."""

    def __init__(self, group: 'SignatureGroup', vendor: str, ptype: str,
                 pattern: str, cves: list[str], can_test: bool):
        super().__init__(timeout=120)
        self._group = group
        self._vendor = vendor
        self._ptype = ptype
        self._pattern = pattern
        self._cves = cves
        self._can_test = can_test
        # Remove test button if not testable type
        if not can_test:
            self.remove_item(self.test_btn)

    @discord.ui.button(label="Test Regex", style=discord.ButtonStyle.primary, row=0)
    async def test_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TestSignatureModal(self._group)
        modal.pattern.default = self._pattern
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Confirm Add", style=discord.ButtonStyle.success, row=0)
    async def confirm_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        loader = self._group._get_loader()
        try:
            if self._ptype == "favicon_hash":
                loader.add_pattern(self._vendor, "favicon_hash", {"hash": int(self._pattern)})
            elif self._ptype == "brand_keyword":
                loader.add_pattern(self._vendor, "brand_keyword", {
                    "pattern": self._pattern, "scope": ["html"], "cves": self._cves
                })
            elif self._ptype == "model":
                loader.add_pattern(self._vendor, "model", {
                    "regex": self._pattern, "scope": ["html", "xml_text"], "cves": self._cves
                })
            elif self._ptype == "version":
                loader.add_pattern(self._vendor, "version", {
                    "regex": self._pattern, "scope": ["html", "xml_text"], "cves": self._cves
                })
            elif self._ptype == "endpoint":
                loader.add_pattern(self._vendor, "endpoint", {
                    "path": self._pattern, "protocol": ["http", "https"]
                })
            elif self._ptype == "onvif":
                loader.add_pattern(self._vendor, "onvif", {"manufacturer_match": [self._vendor]})
            elif self._ptype == "rtsp_path":
                loader.add_pattern(self._vendor, "rtsp_path", {"path": self._pattern})
            elif self._ptype == "extra":
                loader.add_pattern(self._vendor, "extra", {
                    "type": "generic", "regex": self._pattern, "scope": [], "cves": self._cves
                })

            self._group._reload_engine(loader)
            self.stop()
            await interaction.response.edit_message(
                content=f"Added {self._ptype} to **{self._vendor}**. Engine reloaded.",
                embed=None, view=None,
            )
        except Exception as e:
            await interaction.response.edit_message(content=f"Error: {e}", embed=None, view=None)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, row=0)
    async def cancel_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content="Cancelled.", embed=None, view=None)


class AddSignatureModal(discord.ui.Modal, title="Add Signature"):
    """Popup form for adding a new signature pattern."""

    vendor = discord.ui.TextInput(label="Vendor", placeholder="e.g. hikvision, dahua", required=True)
    pattern_type = discord.ui.TextInput(
        label="Type",
        placeholder="brand_keyword | model | version | endpoint | favicon_hash | onvif | rtsp_path | extra",
        required=True, max_length=20,
    )
    pattern = discord.ui.TextInput(
        label="Pattern / Regex / Path",
        placeholder="regex or keyword string or endpoint path",
        required=False, style=discord.TextStyle.paragraph,
    )
    cves = discord.ui.TextInput(label="CVEs (comma-separated)", placeholder="CVE-2021-36260", required=False)

    def __init__(self, group: 'SignatureGroup', pattern_default: str = ""):
        super().__init__()
        self._group = group
        if pattern_default:
            self.pattern.default = pattern_default

    async def on_submit(self, interaction: discord.Interaction):
        vendor = self.vendor.value.strip()
        ptype = self.pattern_type.value.strip()
        pattern = self.pattern.value.strip()
        cves_list = [c.strip() for c in self.cves.value.split(",") if c.strip()] if self.cves.value else []

        if ptype not in ("favicon_hash", "brand_keyword", "model", "version",
                         "endpoint", "onvif", "rtsp_path", "extra"):
            await safe_send(interaction, content=f"Unknown type: {ptype}")
            return

        # Show preview with Test + Confirm buttons
        can_test = ptype in ("brand_keyword", "model", "version") and bool(pattern)
        desc = f"Vendor: **{vendor}**\nType: **{ptype}**\nPattern: `{pattern}`"
        if cves_list:
            desc += f"\nCVEs: {', '.join(cves_list)}"

        view = _AddPreviewView(self._group, vendor, ptype, pattern, cves_list, can_test)
        embed = discord.Embed(title="Preview — Confirm or Test", description=desc, color=0xFEE75C)
        await safe_send(interaction, embed=embed, view=view)


# ---------------------------------------------------------------------------
# Autocomplete helpers
# ---------------------------------------------------------------------------

def _vendor_autocomplete(loader: SignatureLoader, value: str) -> List[app_commands.Choice]:
    return [
        app_commands.Choice(name=s.vendor, value=s.vendor)
        for s in loader.signatures
        if value.lower() in s.vendor.lower()
    ][:25]


PATTERN_TYPES = [
    "brand_keyword", "model", "version", "endpoint",
    "favicon_hash", "onvif", "rtsp_path", "extra",
]


def _type_autocomplete(value: str) -> List[app_commands.Choice]:
    return [
        app_commands.Choice(name=t, value=t)
        for t in PATTERN_TYPES
        if value.lower() in t.lower()
    ][:25]


SCOPE_OPTIONS = ["html", "headers", "xml_text", "json_text", "rtsp_banner", "onvif_response", "ssl_cert"]


# ---------------------------------------------------------------------------
# Command group
# ---------------------------------------------------------------------------

class SignatureGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="signature", description="Manage fingerprint signatures")
        self.bot = bot

    def _get_loader(self) -> SignatureLoader:
        if self.bot._sig_loader:
            return self.bot._sig_loader
        loader = SignatureLoader()
        self.bot._sig_loader = loader
        return loader

    # --- help ---
    @app_commands.command(name="help", description="Show signature command help")
    async def signature_help(self, interaction: discord.Interaction):
        embed = discord.Embed(title="/signature — Fingerprint Signature Management", color=0x5865F2)
        embed.add_field(
            name="/signature list `[vendor]`",
            value="List signature counts for a vendor. Without vendor, opens a\n"
                  "dropdown to pick from all loaded vendors.\n"
                  "Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature show `<vendor>` `[pattern_type]`",
            value="Show detailed signature patterns. Without type, shows a summary\n"
                  "with counts per type. With type (e.g. model, brand_keyword),\n"
                  "shows each pattern with regex, scope, CVEs. Paginated if long.\n"
                  "Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature test",
            value="Opens a form to test a regex against sample text.\n"
                  "If matched, shows result with an 'Add to Signature' button.\n"
                  "If no match, shows 'Edit & Retry' button. Test as many times\n"
                  "as you want before adding. Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature add",
            value="Opens a popup form to add a new signature. Fields: vendor,\n"
                  "type (brand_keyword|model|version|endpoint|favicon_hash|onvif|\n"
                  "rtsp_path|extra), pattern/regex, CVEs. Auto-reloads engine.\n"
                  "Tip: use `/signature test` first to verify your regex. Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature remove `<vendor>` `<pattern_type>` `<index>`",
            value="Remove a specific pattern by index (shown in /signature show).\n"
            "Shows a confirmation prompt before deleting. Auto-reloads engine.\n"
            "Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature export `<vendor>`",
            value="Export a vendor's full YAML signature file as a Discord attachment.\n"
                  "Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature import `<file>`",
            value="Import signatures from an uploaded YAML file. Validates against\n"
                  "the schema, writes to config/signatures/, and reloads the engine.\n"
                  "Works anytime.",
            inline=False,
        )
        embed.add_field(
            name="/signature reload",
            value="Reload all signature YAML files from disk and rebuild the engine.\n"
                  "Also happens automatically every 30 seconds via hot-reload.\n"
                  "Works anytime.",
            inline=False,
        )
        embed.set_footer(text="Signature types: brand_keyword, model, version, endpoint, favicon_hash, onvif, rtsp_path, extra")
        await safe_send(interaction, embed=embed)

    # --- list ---
    @app_commands.command(name="list", description="List signatures (opens dropdown)")
    @app_commands.describe(vendor="Vendor name (optional)")
    async def signature_list(self, interaction: discord.Interaction, vendor: str = ""):
        loader = self._get_loader()

        if vendor:
            sig = self._find_vendor(loader, vendor)
            if not sig:
                await safe_send(interaction, content=f"Vendor not found: {vendor}")
                return
            await self._send_list_embed(interaction, sig)
        else:
            # Show vendor selector dropdown
            view = discord.ui.View(timeout=60)
            select = VendorSelect(loader, lambda i, v: self._on_vendor_selected_list(i, v, loader))
            view.add_item(select)
            await safe_send(interaction, content="Select a vendor to view signatures:", view=view)

    async def _on_vendor_selected_list(self, interaction: discord.Interaction, vendor: str, loader: SignatureLoader):
        sig = loader.get_vendor(vendor)
        if not sig:
            await interaction.response.edit_message(content="Vendor not found.", view=None)
            return
        await self._send_list_embed(interaction, sig, edit=True)

    async def _send_list_embed(self, interaction: discord.Interaction, sig, edit: bool = False):
        type_counts = {
            "brand_keywords": len(sig.brand_keywords),
            "model_patterns": len(sig.model_patterns),
            "version_patterns": len(sig.version_patterns),
            "endpoint_probes": len(sig.endpoint_probes),
            "favicon_hashes": len(sig.favicon_hashes),
            "onvif_parsers": len(sig.onvif_parsers),
            "rtsp_paths": len(sig.rtsp_paths),
            "extra_patterns": len(sig.extra_patterns),
        }

        lines = [f"{name}: {count}" for name, count in type_counts.items()]
        embed = discord.Embed(
            title=f"Signatures: {sig.vendor}",
            description=f"```\n" + "\n".join(lines) + "\n```",
            color=0x5865F2,
        )
        if sig.aliases:
            embed.add_field(name="Aliases", value=", ".join(sig.aliases), inline=False)

        if edit:
            await interaction.response.edit_message(content=None, embed=embed, view=None)
        else:
            await safe_send(interaction, embed=embed)

    # --- show ---
    @app_commands.command(name="show", description="Show signature pattern details")
    @app_commands.describe(vendor="Vendor name", pattern_type="Pattern type to show")
    async def signature_show(
        self, interaction: discord.Interaction,
        vendor: str, pattern_type: Optional[str] = None,
    ):
        await interaction.response.defer()

        loader = self._get_loader()
        sig = self._find_vendor(loader, vendor)
        if not sig:
            await safe_send(interaction, content=f"Vendor not found: {vendor}")
            return

        if pattern_type:
            await self._show_type(interaction, sig, pattern_type)
        else:
            # Show all types summary with counts
            embed = discord.Embed(title=f"Signature: {sig.vendor}", color=0x57F287)
            if sig.aliases:
                embed.add_field(name="Aliases", value=", ".join(sig.aliases), inline=False)

            all_types = {
                "favicon_hash": (sig.favicon_hashes, "Favicon hashes"),
                "brand_keyword": (sig.brand_keywords, "Brand keywords"),
                "model": (sig.model_patterns, "Model patterns"),
                "version": (sig.version_patterns, "Version patterns"),
                "endpoint": (sig.endpoint_probes, "Endpoint probes"),
                "onvif": (sig.onvif_parsers, "ONVIF parsers"),
                "rtsp_path": (sig.rtsp_paths, "RTSP paths"),
                "extra": (sig.extra_patterns, "Extra patterns"),
            }
            for type_name, (items, label) in all_types.items():
                embed.add_field(name=label, value=str(len(items)), inline=True)

            embed.set_footer(text="Use /signature show vendor:... pattern_type:... to see details")
            await safe_send(interaction, embed=embed)

    async def _show_type(self, interaction: discord.Interaction, sig, pattern_type: str):
        items_map = {
            "favicon_hash": (sig.favicon_hashes, lambda h: f"hash={h}"),
            "brand_keyword": (sig.brand_keywords, lambda k: f"pattern=\"{k.pattern}\" scope={k.scope} cves={k.cves}"),
            "model": (sig.model_patterns, lambda p: f"regex=\"{p.regex}\" scope={p.scope} cves={p.cves}"),
            "version": (sig.version_patterns, lambda p: f"regex=\"{p.regex}\" scope={p.scope} normalize={p.normalize or '-'} cves={p.cves}"),
            "endpoint": (sig.endpoint_probes, lambda e: f"path=\"{e.path}\" protocol={e.protocol} content_type={e.content_type or '-'}"),
            "onvif": (sig.onvif_parsers, lambda o: f"manufacturer={o.manufacturer_match} model_tag={o.model_tag} firmware_tag={o.firmware_tag}"),
            "rtsp_path": (sig.rtsp_paths, lambda p: f"path=\"{p}\""),
            "extra": (sig.extra_patterns, lambda e: f"type={e.type} regex=\"{e.regex or '-'}\" scope={e.scope} cves={e.cves}"),
        }

        items, formatter = items_map.get(pattern_type, ([], lambda x: str(x)))

        if not items:
            await safe_send(interaction, content=f"No {pattern_type} patterns for {sig.vendor}")
            return

        # Paginate -- max ~1800 chars per embed
        pages = []
        current_lines = []
        current_len = 0
        for i, item in enumerate(items):
            line = f"[{i}] {formatter(item)}"
            if current_len + len(line) > 1800 and current_lines:
                pages.append("\n".join(current_lines))
                current_lines = []
                current_len = 0
            current_lines.append(line)
            current_len += len(line)
        if current_lines:
            pages.append("\n".join(current_lines))

        embeds = []
        for idx, page_text in enumerate(pages):
            e = discord.Embed(
                title=f"{sig.vendor} -- {pattern_type} ({len(items)})",
                description=f"```\n{page_text}\n```",
                color=0x5865F2,
            )
            if len(pages) > 1:
                e.set_footer(text=f"Page {idx + 1}/{len(pages)}")
            embeds.append(e)

        if len(embeds) > 1:
            view = PaginatedView(embeds)
            await safe_send(interaction, embed=embeds[0], view=view)
        else:
            await safe_send(interaction, embed=embeds[0])

    # --- test (opens test modal) ---
    @app_commands.command(name="test", description="Test a regex pattern against sample text")
    async def signature_test(self, interaction: discord.Interaction):
        modal = TestSignatureModal(self)
        await interaction.response.send_modal(modal)

    # --- add (opens modal) ---
    @app_commands.command(name="add", description="Add a new signature (opens form)")
    async def signature_add(self, interaction: discord.Interaction):
        modal = AddSignatureModal(self)
        await interaction.response.send_modal(modal)

    # --- remove (with confirmation) ---
    @app_commands.command(name="remove", description="Remove a signature pattern")
    @app_commands.describe(vendor="Vendor name", pattern_type="Pattern type", index="Index (from /signature show)")
    async def signature_remove(
        self, interaction: discord.Interaction,
        vendor: str, pattern_type: str, index: int
    ):
        loader = self._get_loader()
        sig = self._find_vendor(loader, vendor)
        if not sig:
            await safe_send(interaction, content=f"Vendor not found: {vendor}")
            return

        # Preview what will be removed
        items_map = {
            "favicon_hash": sig.favicon_hashes,
            "brand_keyword": sig.brand_keywords,
            "model": sig.model_patterns,
            "version": sig.version_patterns,
            "endpoint": sig.endpoint_probes,
            "onvif": sig.onvif_parsers,
            "rtsp_path": sig.rtsp_paths,
            "extra": sig.extra_patterns,
        }
        items = items_map.get(pattern_type, [])
        if index < 0 or index >= len(items):
            await safe_send(interaction, content=f"Index {index} out of range (0-{len(items) - 1})")
            return

        embed = discord.Embed(
            title=f"Remove signature?",
            description=f"**Vendor:** {vendor}\n**Type:** {pattern_type}\n**Index:** {index}\n**Item:** {items[index]}",
            color=0xED4245,
        )

        async def on_confirm(i: discord.Interaction):
            removed = loader.remove_pattern(vendor, pattern_type, index)
            if removed:
                self._reload_engine(loader)
                await i.response.edit_message(
                    content=f"Removed {vendor}/{pattern_type}[{index}]. Engine reloaded.",
                    embed=None, view=None,
                )
            else:
                await i.response.edit_message(content="Remove failed.", embed=None, view=None)

        view = ConfirmView(on_confirm)
        await safe_send(interaction, embed=embed, view=view)

    # --- export ---
    @app_commands.command(name="export", description="Export vendor signatures as YAML file")
    @app_commands.describe(vendor="Vendor name")
    async def signature_export(self, interaction: discord.Interaction, vendor: str):
        loader = self._get_loader()
        sig = loader.get_vendor(vendor)
        if not sig:
            await safe_send(interaction, content=f"Vendor not found: {vendor}")
            return

        from pathlib import Path
        filepath = Path(loader._dir) / f"{vendor}.yaml"
        if not filepath.exists():
            await safe_send(interaction, content=f"YAML file not found")
            return

        with open(filepath) as f:
            content = f.read()

        file = discord.File(io.BytesIO(content.encode()), filename=f"{vendor}.yaml")
        await safe_send(interaction, file=file)

    # --- import ---
    @app_commands.command(name="import", description="Import signatures from a YAML file")
    @app_commands.describe(file="YAML file to import")
    async def signature_import(self, interaction: discord.Interaction, file: discord.Attachment):
        loader = self._get_loader()

        try:
            raw = await file.read()
            content = raw.decode("utf-8")
        except Exception as e:
            await safe_send(interaction, content=f"Failed to read file: {e}")
            return

        try:
            import yaml
            from src.layers.layer2_fingerprinter.signatures.schema import VendorSignature
            data = yaml.safe_load(content)
            sig = VendorSignature(**data)
        except Exception as e:
            await safe_send(interaction, content=f"Invalid YAML: {e}")
            return

        from pathlib import Path
        filepath = Path(loader._dir) / f"{sig.vendor}.yaml"
        with open(filepath, "w") as f:
            f.write(content)

        before, after = loader.reload()
        self._reload_engine(loader)

        await safe_send(
            interaction,
            content=f"Imported **{sig.vendor}** ({before} -> {after} vendors). Engine reloaded.",
        )

    # --- reload ---
    @app_commands.command(name="reload", description="Reload all signatures from disk")
    async def signature_reload(self, interaction: discord.Interaction):
        loader = self._get_loader()
        before, after = loader.reload()
        self._reload_engine(loader)

        embed = discord.Embed(title="Signatures Reloaded", color=0x57F287)
        embed.add_field(name="Before", value=str(before), inline=True)
        embed.add_field(name="After", value=str(after), inline=True)
        await safe_send(interaction, embed=embed)

    # --- helpers ---

    def _find_vendor(self, loader: SignatureLoader, name: str):
        sig = loader.get_vendor(name)
        if sig:
            return sig
        for s in loader.signatures:
            if name.lower() in [a.lower() for a in s.aliases]:
                return s
        return None

    def _reload_engine(self, loader: SignatureLoader):
        engine = SignatureEngine(loader.signatures)

        if self.bot.fingerprinter and hasattr(self.bot.fingerprinter, '_engine'):
            self.bot.fingerprinter._engine = engine
            self.bot.fingerprinter._loader = loader

            endpoints = loader.get_unique_endpoint_paths()
            rtsp_paths = loader.get_all_rtsp_paths()
            for prober in self.bot.fingerprinter._probers:
                if isinstance(prober, (HTTPProber, HTTPSProber)):
                    prober.set_endpoints(endpoints)
                elif isinstance(prober, RTSPProber):
                    from src.layers.layer2_fingerprinter.probers.rtsp_prober import _DEFAULT_RTSP_PATHS
                    prober._paths = list(_DEFAULT_RTSP_PATHS)
                    seen = set(prober._paths)
                    for p in rtsp_paths:
                        if p not in seen:
                            prober._paths.append(p)
                            seen.add(p)
