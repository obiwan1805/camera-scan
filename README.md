# Camera Scanner

Massive IP camera discovery, fingerprinting, and vulnerability assessment pipeline with a Discord bot interface.

## Architecture

```
CIDR Input → Layer 1 (Masscan) → Durable Queue → Layer 2 (Fingerprinter) → Queue → [Layer 3 — future]
```

- **Layer 1** — Masscan-based port scanner. Scans CIDR ranges at configurable rate, outputs discovered IP:port pairs.
- **Layer 2** — Multi-protocol fingerprinter. Probes each target via HTTP, HTTPS, RTSP, ONVIF, SSH using semaphore-bounded concurrency. Identifies vendor, model, and firmware.
- **Durable Queue** — SQLite-backed claim system. Crashed/stopped scans recover automatically on restart.

### Pause vs Stop

- **Pause** (`/scan pause`) — Sends SIGINT to masscan (writes `paused.conf`), keeps DB state. Next `/scan start` resumes from where it left off.
- **Stop** (`/scan stop`) — Sends SIGTERM, deletes `paused.conf`. Next `/scan start` begins fresh.

## Setup

### 1. Install masscan

```bash
sudo apt update
sudo apt install masscan
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure

Edit `config/default.yaml`:

```yaml
layers:
  scan_rate: 5000          # packets per second
  output_file: data/scans/results.txt
  layer2:
    worker_pool:
      max_concurrent: 200  # concurrent fingerprint probes
    modules:               # probe modules to use
      - favicon
      - http
      - https
      - rtsp
      - onvif
      - ssh
```

### 4. CIDR ranges

Put target CIDR ranges in `data/cidrs.txt`, one per line:

```
192.168.0.0/16
10.0.0.0/8
```

### 5. Ports

Put target ports in `data/ports.txt`, one per line:

```
80
443
554
8080
8554
```

### 6. Discord bot

Create a `.env` file:

```
DISCORD_BOT_TOKEN=your_token_here
DISCORD_GUILD_ID=your_server_id
```

`DISCORD_GUILD_ID` is optional but recommended — commands sync instantly to a specific server instead of globally (which takes up to an hour).

## Usage

### CLI (headless)

```bash
sudo -E python3 main.py
```

### Discord bot

```bash
sudo -E python3 bot.py
```

## Discord Commands

### Scan Controls

| Command | Description |
|---------|-------------|
| `/scan start` | Start or resume the scan pipeline |
| `/scan pause` | Pause scan (resumable) |
| `/scan stop` | Stop scan (fresh start next time) |
| `/scan progress` | Live stats: IPs scanned, discovered, fingerprinted |

### Runtime Config

| Command | Description |
|---------|-------------|
| `/config show` | Display current parameters |
| `/config scan_rate <n>` | Set packets/sec (next scan) |
| `/config max_concurrent <n>` | Set max concurrent probes (next scan) |
| `/config batch_size <n>` | Set DB write batch size (next scan) |

### PoC Scripts

| Command | Description |
|---------|-------------|
| `/poc add name:... file:<upload>` | Add PoC via file upload |
| `/poc add name:... script_content:"..."` | Add PoC via text |
| `/poc list [vendor:...]` | List PoCs, optional vendor filter |
| `/poc show id:<n>` | Full details with script |
| `/poc remove id:<n>` | Delete PoC |

### Password Dictionaries

| Command | Description |
|---------|-------------|
| `/dict add dict_type:... value:...` | Add single entry |
| `/dict import dict_type:... file:<upload>` | Bulk import (one entry per line) |
| `/dict show dict_type:...` | Show entries of a type |
| `/dict list` | List all dict types with counts |
| `/dict remove id:<n>` | Delete entry |

Dict types: `default_usernames`, `default_passwords`, `default_creds` (user:pass pairs), or any custom name.

### Targets

| Command | Description |
|---------|-------------|
| `/target add name:... [vendor] [category] [aliases]` | Add target |
| `/target list [vendor:...]` | List targets |
| `/target show id:<n>` | Full details |
| `/target remove id:<n>` | Delete target |

## Storage

SQLite with WAL mode. Single writer coroutine for safe concurrent writes.

| Table | Purpose |
|-------|---------|
| `port_scans` | Discovered open ports (IP, port, status) |
| `fingerprints` | Fingerprint results (vendor, model, evidence) |
| `raw_responses` | Raw HTTP/RTSP/ONVIF responses |
| `claims` | Durable queue state (pending/claimed/done/failed) |
| `pocs` | PoC scripts |
| `dicts` | Password/credential dictionaries |
| `targets` | Known camera/NVR/DVR models |

## Project Structure

```
bot.py                          # Discord bot entry point
main.py                         # CLI entry point
config/default.yaml             # Configuration
data/
  cidrs.txt                     # CIDR ranges to scan
  ports.txt                     # Ports to scan
  camera_scan.db                # SQLite database
src/
  bot/
    bot.py                      # ScanBot class, pipeline lifecycle
    scan.py                     # /scan commands
    config.py                   # /config commands
    poc.py                      # /poc commands
    dict.py                     # /dict commands
    target.py                   # /target commands
    common.py                   # Shared utilities
  core/
    config.py                   # YAML config loader
    interfaces.py               # Abstract interfaces
    durable_queue.py            # SQLite-backed durable queue
  layers/
    layer1_port_scanner/
      scanner.py                # Masscan wrapper + file watcher
    layer2_fingerprinter/
      fingerprinter.py          # Semaphore-bounded multi-probe
      modules/
        http.py                 # HTTP probe (HTML, headers)
        https.py                # HTTPS probe
        rtsp.py                 # RTSP DESCRIBE probe
        onvif.py                # ONVIF WS-Discovery probe
        ssh.py                  # SSH banner probe
        favicon.py              # Favicon hash matching
  pipeline/
    builder.py                  # Pipeline construction + lifecycle
  storage/
    base.py                     # StorageBackend interface
    sqlite_backend.py           # SQLite implementation
    schemas.py                  # Pydantic models
  utils/
    network.py                  # IP counting, CIDR/range parsing
    logging.py                  # Logger setup
```

## Notes

- `sudo` is required for masscan (raw socket access)
- Files created by `sudo` will be owned by root — fix with `sudo chown $USER:$USER data/camera_scan.db*`
- The persistent DB (`self.bot.db`) is initialized on bot startup — `/poc`, `/dict`, `/target` commands work without running a scan
- The pipeline creates a separate DB connection for scan writes, which is disconnected when the scan stops
