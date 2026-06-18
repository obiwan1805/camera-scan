"""Config command group — /config show|scan_rate|max_concurrent|prober_timeout|raw_responses|help."""
import yaml
from pathlib import Path
import discord
from discord import app_commands
from .common import safe_send

_CONFIG_PATH = Path("config/default.yaml")

# Maps /config command keys to their YAML paths
_CONFIG_MAP = {
    "scan_rate":           ("layers", "layer1", "scan_rate"),
    "masscan_wait":        ("layers", "layer1", "wait"),
    "max_concurrent":      ("layers", "layer2", "worker_pool", "max_concurrent"),
    "prober_timeout":      ("layers", "layer2", "prober_timeout"),
    "import_feed_batch":   ("layers", "layer2", "import_feed_batch"),
    "import_feed_interval":("layers", "layer2", "import_feed_interval"),
    "batch_size":          ("layers", "layer1", "batch_size"),
    "raw_responses":       ("layers", "layer2", "log_raw_responses"),
}


def _save_to_yaml(key: str, value) -> None:
    """Write a single config value back to config/default.yaml."""
    path = _CONFIG_PATH
    data = {}
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}

    keys = _CONFIG_MAP[key]
    node = data
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value

    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


class ConfigGroup(app_commands.Group):
    def __init__(self, bot: 'ScanBot'):
        super().__init__(name="config", description="Configure scan parameters")
        self.bot = bot

    def _check_idle(self, interaction: discord.Interaction) -> bool:
        return self.bot._status == "idle"

    @app_commands.command(name="help", description="Show config command help")
    async def config_help(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="/config — Runtime Configuration",
            description=(
                "Tune scan parameters at runtime. **All changes are saved to "
                "config/default.yaml** and survive bot restarts.\n\n"
                "Changes apply on the **next** `/scan start`."
            ),
            color=0x5865F2,
        )

        embed.add_field(
            name="Layer 1 — Masscan",
            value=(
                "`/config scan_rate <n>` — packets/sec (default: 1,000)\n"
                "`/config masscan_wait <n>` — probe wait in sec (1-300, default: 10)"
            ),
            inline=False,
        )

        embed.add_field(
            name="Layer 2 — Fingerprinter",
            value=(
                "`/config max_concurrent <n>` — concurrent probes (default: 200)\n"
                "`/config prober_timeout <n>` — probe timeout in sec (1-60, default: 10)\n"
                "`/config raw_responses <bool>` — store prober raw responses to DB (default: false)"
            ),
            inline=False,
        )

        embed.add_field(
            name="Masscan Import Feed",
            value=(
                "`/config import_feed_batch <n>` — entries per batch (1-10000, default: 100)\n"
                "`/config import_feed_interval <n>` — sec between batches (1-300, default: 5)"
            ),
            inline=False,
        )

        embed.add_field(
            name="Other",
            value="`/config show` — Display all current values (works anytime)",
            inline=False,
        )

        embed.add_field(
            name="Tuning tips",
            value=(
                "```\n"
                "Fast + noisy:    scan_rate 10000, max_concurrent 500\n"
                "Slow + stealthy: scan_rate 200,  max_concurrent 50\n"
                "Slow network:    masscan_wait 30, prober_timeout 20\n"
                "Huge import:     import_feed_batch 30, interval 10\n"
                "```"
            ),
            inline=False,
        )

        embed.set_footer(text="All setters require scan to be idle. See also: /scan help")
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="show", description="Show current config values")
    async def config_show(self, interaction: discord.Interaction):
        embed = self.bot._build_config_embed()
        await safe_send(interaction, embed=embed)

    @app_commands.command(name="scan_rate", description="Set masscan rate (packets/sec)")
    @app_commands.describe(value="Masscan rate in packets/sec")
    async def config_scan_rate(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["scan_rate"] = value
        _save_to_yaml("scan_rate", value)
        await safe_send(interaction, content=f"scan_rate set to **{value:,} pps** — saved to config.")

    @app_commands.command(name="masscan_wait", description="Set masscan per-probe timeout (seconds)")
    @app_commands.describe(value="Seconds to wait per probe")
    async def config_masscan_wait(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        if value < 1 or value > 300:
            await safe_send(interaction, content="masscan_wait must be between 1 and 300 seconds.")
            return
        self.bot._overrides["masscan_wait"] = value
        _save_to_yaml("masscan_wait", value)
        await safe_send(interaction, content=f"masscan_wait set to **{value}s** — masscan waits up to {value}s per probe. Saved to config.")

    @app_commands.command(name="max_concurrent", description="Set max concurrent fingerprinter tasks")
    @app_commands.describe(value="Max concurrent tasks")
    async def config_max_concurrent(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["max_concurrent"] = value
        _save_to_yaml("max_concurrent", value)
        await safe_send(interaction, content=f"max_concurrent set to **{value}** — saved to config.")

    @app_commands.command(name="prober_timeout", description="Set prober request timeout (seconds)")
    @app_commands.describe(value="Timeout in seconds")
    async def config_prober_timeout(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        if value < 1 or value > 60:
            await safe_send(interaction, content="prober_timeout must be between 1 and 60 seconds.")
            return
        self.bot._overrides["prober_timeout"] = value
        _save_to_yaml("prober_timeout", value)
        await safe_send(interaction, content=f"prober_timeout set to **{value}s** — all probers will wait up to {value}s. Saved to config.")

    @app_commands.command(name="import_feed_batch", description="Set masscan import feed batch size")
    @app_commands.describe(value="Entries per feed batch")
    async def config_import_feed_batch(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        if value < 1 or value > 10000:
            await safe_send(interaction, content="import_feed_batch must be between 1 and 10,000.")
            return
        self.bot._overrides["import_feed_batch"] = value
        _save_to_yaml("import_feed_batch", value)
        await safe_send(interaction, content=f"import_feed_batch set to **{value}** — will feed {value} entries per batch during import. Saved to config.")

    @app_commands.command(name="import_feed_interval", description="Set seconds between import feed batches")
    @app_commands.describe(value="Seconds between batches")
    async def config_import_feed_interval(self, interaction: discord.Interaction, value: int):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        if value < 1 or value > 300:
            await safe_send(interaction, content="import_feed_interval must be between 1 and 300 seconds.")
            return
        self.bot._overrides["import_feed_interval"] = value
        _save_to_yaml("import_feed_interval", value)
        await safe_send(interaction, content=f"import_feed_interval set to **{value}s** — will wait {value}s between feed batches. Saved to config.")

    @app_commands.command(name="raw_responses", description="Toggle storing prober raw responses to DB")
    @app_commands.describe(value="True to log raw responses, False to skip")
    async def config_raw_responses(self, interaction: discord.Interaction, value: bool):
        if not self._check_idle(interaction):
            await safe_send(interaction, content="Cannot change config while scan is running.")
            return
        self.bot._overrides["raw_responses"] = value
        _save_to_yaml("raw_responses", value)
        state = "ON — prober responses stored to raw_responses table" if value else "OFF — prober responses discarded after matching"
        await safe_send(interaction, content=f"raw_responses logging **{state}**. Saved to config.")
