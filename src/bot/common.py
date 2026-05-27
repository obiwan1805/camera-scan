"""Shared utilities for Discord bot command groups."""
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
