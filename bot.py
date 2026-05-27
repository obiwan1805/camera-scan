"""Entry point for the camera-scan Discord bot."""
import os
from dotenv import load_dotenv

load_dotenv()

from src.bot import ScanBot

token = os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("BOT_TOKEN")
if not token:
    print("Error: DISCORD_BOT_TOKEN or BOT_TOKEN environment variable is required")
    exit(1)

bot = ScanBot()
bot.run(token)
