# Camera Scanner

Massive IP camera discovery, fingerprinting, and vulnerability assessment pipeline controlled via a Discord bot.

Tested with **masscan 1.3.2-241-g94e118c** (built from source, Ubuntu 22.04, gcc 11.4.0).

## What it does

1. **Discover** — Masscan sweeps CIDRs/IP ranges for open camera ports (80, 554, 8080, 8554, etc.)
2. **Fingerprint** — Multi-protocol probers (HTTP/HTTPS/RTSP/ONVIF/favicon) gather data from each host
3. **Identify** — A signature engine matches collected data against vendor YAML files to identify vendor, model, and firmware version
4. **Score** — Each result gets a confidence weight based on what was extracted (full model+version = 1.0)

All of this is controlled through Discord slash commands. You add targets, start scans, and query results without leaving the chat.

## Architecture

```
DB Targets → Layer 1 (Masscan) → Durable Queue → Layer 2 (Fingerprinter) → SQLite Storage
```

- **Layer 1** — Masscan subprocess. Takes targets from DB, writes `ip:port` pairs to a durable SQLite queue. Supports pause/resume via `paused.conf`.
- **Layer 2** — Fingerprinter. For each `ip:port`, runs 5 probers concurrently (HTTP, HTTPS, RTSP, ONVIF, favicon), then matches all signatures against collected data, then aggregates into a single best fingerprint.
- **Durable Queue** — SQLite-backed claim system. Crashed scans recover automatically on restart.

See **[docs/USAGE.md](docs/USAGE.md)** for full command reference and workflows.

## Quick Start

### 1. Build masscan from source

```bash
sudo apt update
sudo apt install -y git gcc make libpcap-dev

git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make -j$(nproc)
sudo cp bin/masscan /usr/local/bin/
```

Verify:

```
$ masscan --version
Masscan version 1.3.2-241-g94e118c
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure ports

Put target ports in `data/ports.txt`, one per line:

```
80
443
554
8080
8554
```

### 4. Discord bot setup

Create a `.env` file:

```
DISCORD_BOT_TOKEN=your_token_here
DISCORD_GUILD_ID=your_server_id
```

`DISCORD_GUILD_ID` is optional but recommended — commands sync instantly to a specific server instead of globally (which takes up to an hour).

### 5. Run

```bash
sudo -E python3 bot.py
```

`sudo` is required because masscan needs raw socket access.

### Target management from the shell (no Discord)

For prep work — bulk-loading CIDR lists, staging masscan output — use the CLI:

```bash
python3 main.py add 192.168.1.0/24
python3 main.py import my_targets.txt
python3 main.py import-masscan masscan_results.txt
python3 main.py list
```

See **[docs/CLI.md](docs/CLI.md)** for the full reference. The CLI writes to the same DB as the bot, so anything staged from the shell is picked up by the next `/scan start`.

## Basic Workflow

```
/target add 192.168.1.0/24          # add scan target
/scan start                         # begin scanning
/scan progress                      # check live stats
/scan pause                         # pause (resumable)
/scan start                         # resume
```

For importing existing masscan output instead of running masscan live:

```
/target import-masscan <file>       # stage masscan -oL output
/scan start                         # runs Layer 2 only (no masscan)
```

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — Full Discord command reference, workflows, and feature guides
- **[docs/CLI.md](docs/CLI.md)** — `main.py` shell CLI for target management (no Discord required)
- **[docs/SIGNATURES.md](docs/SIGNATURES.md)** — How to write and manage fingerprint signatures (the most important feature for customization)

## Notes

- `sudo` is required for masscan (raw socket access)
- Files created by `sudo` will be owned by root — fix with `sudo chown $USER:$USER data/camera_scan.db*`
- Signatures hot-reload every 30 seconds — edit YAML files in `config/signatures/` and they take effect without restarting
- Masscan import mode runs Layer 2 only — no masscan subprocess, no root required
