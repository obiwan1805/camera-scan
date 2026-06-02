# Camera Scanner

Massive IP camera discovery, fingerprinting, and vulnerability assessment pipeline with a Discord bot interface.

## Architecture

```
CIDR Input → Layer 1 (Masscan) → Durable Queue → Layer 2 (Fingerprinter) → Queue → [Layer 3 — future]
```

- **Layer 1** — Masscan-based port scanner. Scans CIDR ranges at configurable rate, outputs discovered IP:port pairs.
- **Layer 2** — YAML-driven multi-protocol fingerprinter. Three-phase pipeline: **collect** (HTTP/HTTPS/RTSP/ONVIF/Favicon probers) → **match** (run ALL vendor signatures against collected data) → **resolve** (majority vote for vendor, longest value for model/version).
- **Durable Queue** — SQLite-backed claim system. Crashed/stopped scans recover automatically on restart.

### Layer 2 Pipeline

```
(ip, port) → Probers (collect raw data) → Engine (match ALL signatures) → Resolver (pick best) → Fingerprint
```

1. **Collect** — Five probers fetch raw data into `CollectedData`. Zero signature logic.
   - HTTPProber: GET `/` for HTML + headers, then probes all signature-defined endpoints
   - HTTPSProber: Same with TLS, extracts cert subject for SSL matching
   - RTSPProber: DESCRIBE + OPTIONS on signature-defined + generic RTSP paths
   - ONVIFProber: SOAP GetDeviceInformation
   - FaviconProber: Downloads favicon, computes MMH3 hash

2. **Match** — `SignatureEngine` runs ALL vendor signatures (from YAML files) against ALL data buckets. Every match is collected — no early stopping.

3. **Resolve** — `AggregationResolver` picks the best result:
   - Vendor: majority vote from brand keyword / favicon / ONVIF matches
   - Model: longest value (most specific) among winning vendor
   - Version: longest value among winning vendor
   - CVEs: union of all CVEs from all winning matches

### Signature System

8 signature types, each defined per-vendor in YAML:

| Type | YAML key | Engine action |
|------|----------|---------------|
| favicon_hash | `favicon_hashes` | Integer MMH3 hash lookup |
| brand_keyword | `brand_keywords` | Regex search in text scopes |
| model | `model_patterns` | Regex search, extract group |
| version | `version_patterns` | Regex search, extract, normalize |
| endpoint | `endpoint_probes` | Feeds xml/json texts (indirect) |
| onvif | `onvif_parsers` | XML tag extraction from ONVIF response |
| rtsp_path | `rtsp_paths` | Feeds rtsp_banner (indirect) |
| extra | `extra_patterns` | Dispatch by type (e.g. ssl_cn) |

Signatures support `case_sensitive: true` on model/version patterns to prevent false positives (e.g., distinguishing real Vivotek model FD9187 from webpack hash fd34c8dc).

Hot-reload: the engine checks signature file mtimes every 30 seconds and atomically swaps without restarting.

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
    signatures_dir: config/signatures
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

### Running tests

```bash
python3 -m pytest tests/ -v
```

## Discord Commands

Every command group has a `/<group> help` subcommand showing full usage details.

### Scan Controls

| Command | Description |
|---------|-------------|
| `/scan start` | Start or resume the scan pipeline |
| `/scan pause` | Pause scan (resumable) |
| `/scan stop` | Stop scan (fresh start next time) |
| `/scan progress` | Live stats: IPs scanned, discovered, fingerprinted |
| `/scan help` | Show detailed help for scan commands |

### Runtime Config

| Command | Description |
|---------|-------------|
| `/config show` | Display current parameters |
| `/config scan_rate <n>` | Set packets/sec (next scan) |
| `/config max_concurrent <n>` | Set max concurrent probes (next scan) |
| `/config batch_size <n>` | Set DB write batch size (next scan) |
| `/config help` | Show detailed help for config commands |

### Fingerprint Signatures

| Command | Description |
|---------|-------------|
| `/signature list [vendor]` | List signature counts for a vendor (dropdown if no vendor) |
| `/signature show <vendor> [type]` | Show pattern details, paginated |
| `/signature add` | Opens popup form to add a new signature |
| `/signature remove <vendor> <type> <index>` | Remove a pattern (with confirmation) |
| `/signature export <vendor>` | Export vendor YAML as file attachment |
| `/signature import <file>` | Import signatures from YAML file |
| `/signature reload` | Reload all YAML from disk |
| `/signature help` | Show detailed help for signature commands |

### PoC Scripts

| Command | Description |
|---------|-------------|
| `/poc add name:... file:<upload>` | Add PoC via file upload |
| `/poc add name:... script_content:"..."` | Add PoC via text |
| `/poc list [vendor:...]` | List PoCs, optional vendor filter |
| `/poc show id:<n>` | Full details with script |
| `/poc remove id:<n>` | Delete PoC |
| `/poc help` | Show detailed help for PoC commands |

### Password Dictionaries

| Command | Description |
|---------|-------------|
| `/dict add dict_type:... value:...` | Add single entry |
| `/dict import dict_type:... file:<upload>` | Bulk import (one entry per line) |
| `/dict show dict_type:...` | Show entries of a type |
| `/dict list` | List all dict types with counts |
| `/dict remove id:<n>` | Delete entry |
| `/dict help` | Show detailed help for dict commands |

Dict types: `default_usernames`, `default_passwords`, `default_creds` (user:pass pairs), or any custom name.

### Targets

| Command | Description |
|---------|-------------|
| `/target add name:... [vendor] [category] [aliases]` | Add target |
| `/target list [vendor:...]` | List targets |
| `/target show id:<n>` | Full details |
| `/target remove id:<n>` | Delete target |
| `/target help` | Show detailed help for target commands |

## Storage

SQLite with WAL mode. Single writer coroutine for safe concurrent writes.

| Table | Purpose |
|-------|---------|
| `port_scans` | Discovered open ports (IP, port, status) |
| `fingerprints` | Fingerprint results (vendor, model, evidence_items, CVEs) |
| `raw_responses` | Raw HTTP/RTSP/ONVIF responses |
| `claims` | Durable queue state (pending/claimed/done/failed) |
| `pocs` | PoC scripts |
| `dicts` | Password/credential dictionaries |
| `targets` | Known camera/NVR/DVR models |

## Project Structure

```
bot.py                          # Discord bot entry point
main.py                         # CLI entry point
config/
  default.yaml                  # Configuration
  signatures/                   # YAML signature files per vendor
    _generic.yaml
    hikvision.yaml
    dahua.yaml
    axis.yaml
    vivotek.yaml
    ...
data/
  cidrs.txt                     # CIDR ranges to scan
  ports.txt                     # Ports to scan
  camera_scan.db                # SQLite database
src/
  bot/
    bot.py                      # ScanBot class, pipeline lifecycle
    scan.py                     # /scan commands
    config.py                   # /config commands
    signature.py                # /signature commands (modal, dropdown, pagination)
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
      fingerprinter.py          # Orchestrates collect/match/resolve pipeline
      engine.py                 # Runs ALL signatures against collected data
      resolver.py               # Majority vote vendor, longest model/version
      signatures/
        schema.py               # Pydantic models for YAML signatures
        loader.py               # YAML loader + hot-reload + CRUD
      probers/
        http_prober.py          # HTTP: root page, headers, endpoint probes
        https_prober.py         # HTTPS: same + SSL cert extraction
        rtsp_prober.py          # RTSP: DESCRIBE on signature paths
        onvif_prober.py         # ONVIF: SOAP GetDeviceInformation
        favicon_prober.py       # Favicon MMH3 hash
        types.py                # CollectedData model
        base.py                 # Prober ABC
  pipeline/
    builder.py                  # Pipeline construction + lifecycle
  storage/
    base.py                     # StorageBackend interface
    sqlite_backend.py           # SQLite implementation
    schemas.py                  # Pydantic models (Fingerprint, EvidenceItem, etc.)
  utils/
    network.py                  # IP counting, CIDR/range parsing
    logging.py                  # Logger setup
tests/
  test_engine.py                # Engine, resolver, normalization tests
  test_engine_edge.py           # Edge cases, loader round-trip, hot-reload tests
```

## Notes

- `sudo` is required for masscan (raw socket access)
- Files created by `sudo` will be owned by root — fix with `sudo chown $USER:$USER data/camera_scan.db*`
- The persistent DB (`self.bot.db`) is initialized on bot startup — `/poc`, `/dict`, `/target` commands work without running a scan
- The pipeline creates a separate DB connection for scan writes, which is disconnected when the scan stops
- Signatures hot-reload every 30 seconds — edit YAML files in `config/signatures/` and they take effect without restarting
