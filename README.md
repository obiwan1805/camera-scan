# Camera Scanner

Massive IP camera discovery, fingerprinting, and vulnerability assessment pipeline with a Discord bot interface.

## Architecture

```
DB Targets → Layer 1 (Masscan) → Durable Queue → Layer 2 (Fingerprinter) → Queue → [Layer 3 — future]
```

Targets (CIDRs, IPs, ranges) are stored in the database and managed via Discord commands. Masscan output can also be imported directly for standalone Layer 2 fingerprinting.

### Layer 1 — Port Discovery

Masscan-based port scanner. Takes targets from the database, scans at a configurable rate (packets/sec), and outputs discovered `ip:port` pairs into a durable SQLite-backed queue. Supports pause/resume — interrupted scans pick up where they left off via `paused.conf`.

### Layer 2 — Device Fingerprinting

Multi-protocol fingerprinter with a three-phase pipeline:

```
(ip, port) → Collect → Match → Resolve → Fingerprint
```

**Collect** — Five probers fetch raw data from each target concurrently. Sessions are reused across probes. No signature logic here — they just gather bytes.

| Prober | What it does |
|--------|-------------|
| HTTP | GET `/` for HTML + headers, then probes signature-defined endpoints concurrently |
| HTTPS | Same as HTTP over TLS, also extracts SSL certificate subject |
| RTSP | DESCRIBE on signature-defined and generic RTSP paths |
| ONVIF | SOAP GetDeviceInformation request |
| Favicon | Downloads favicon, computes MMH3 hash |

**Match** — The signature engine runs ALL vendor signatures (loaded from YAML) against ALL collected data. No early stopping — every match is recorded. Signatures are organized into types:

| Type | What it matches |
|------|----------------|
| `brand_keywords` | Regex patterns in HTML, headers, RTSP banners |
| `model_patterns` | Regex with capture groups for model extraction |
| `version_patterns` | Regex with optional normalization (e.g. prefix `v`) |
| `favicon_hashes` | Integer MMH3 hash comparison |
| `endpoint_probes` | HTTP paths that feed XML/JSON data into the matcher |
| `onvif_parsers` | Manufacturer, model, firmware XML tag extraction |
| `rtsp_paths` | RTSP URLs that feed banner data into the matcher |
| `extra_patterns` | Extensible (e.g. SSL CN matching) |

Patterns support `case_sensitive` mode and CVE annotations per match.

**Resolve** — The aggregator picks the best fingerprint from all matches:
- **Vendor**: majority vote with total match count as tiebreaker (requires at least one brand/favicon/ONVIF match)
- **Model/version**: longest value wins (most specific)
- **CVEs**: union across all matching patterns
- All evidence is preserved for auditability

Concurrency is controlled by a semaphore acquired *before* task creation, ensuring the configured max_concurrent limit is actually enforced.

### Durable Queue

SQLite-backed claim system between layers. Items move through `pending → claimed → done/failed`. On enqueue, items are inserted directly as `claimed` to avoid a separate claim step. Crashed or stopped scans recover automatically on restart — unclaimed items are reprocessed. Old completed/failed claims are cleaned up periodically.

### Signatures

Defined per vendor as YAML files in `config/signatures/`. Adding a new vendor or pattern is a single YAML edit — no Python changes needed. The engine hot-reloads every 30 seconds by checking file modification times and atomically swapping the signature set.

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

### 4. Ports

Put target ports in `data/ports.txt`, one per line:

```
80
443
554
8080
8554
```

### 5. Discord bot

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
| `/scan start` | Start or resume the scan pipeline. Requires targets or staged masscan import |
| `/scan pause` | Pause scan (waits for full pipeline stop, resumable) |
| `/scan stop` | Stop scan and delete paused.conf (fresh start next time) |
| `/scan progress` | Live stats: IPs scanned, discovered, fingerprinted, queue depth |

### Targets

| Command | Description |
|---------|-------------|
| `/target add <target>` | Add IP, CIDR, or IP range (e.g. `192.168.1.0/24`) |
| `/target remove <id>` | Remove target by ID |
| `/target list [type]` | List all targets with pagination (works during scan) |
| `/target import <file>` | Bulk import targets from text file |
| `/target export` | Export targets to `data/cidrs.txt` |
| `/target clear` | Remove all targets (with confirmation) |
| `/target import-masscan <file>` | Import masscan `-oL` output for standalone fingerprinting |

Target commands (except list) require scan to be idle. Masscan import stages a file — use `/scan start` to begin Layer 2-only fingerprinting.

### Runtime Config

| Command | Description |
|---------|-------------|
| `/config show` | Display current parameters |
| `/config scan_rate <n>` | Set packets/sec (applies on next scan) |
| `/config max_concurrent <n>` | Set max concurrent probes (applies on next scan) |
| `/config batch_size <n>` | Set DB write batch size (applies on next scan) |

### Fingerprint Signatures

| Command | Description |
|---------|-------------|
| `/signature list [vendor]` | List signature counts (dropdown if no vendor) |
| `/signature show <vendor> [type]` | Show pattern details, paginated |
| `/signature test` | Test regex against sample text before adding |
| `/signature add` | Preview form with test/confirm/cancel buttons |
| `/signature remove <vendor> <type> <index>` | Remove pattern (with confirmation) |
| `/signature export <vendor>` | Export vendor YAML as file attachment |
| `/signature import <file>` | Import signatures from YAML file |
| `/signature reload` | Reload all YAML from disk |

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
| `targets` | Scan inputs — IPs, CIDRs, IP ranges |

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
  ports.txt                     # Ports to scan
  masscan_import.txt            # Staged masscan import (created by /target import-masscan)
  camera_scan.db                # SQLite database
src/
  bot/
    bot.py                      # ScanBot class, pipeline lifecycle
    scan.py                     # /scan commands
    config.py                   # /config commands
    signature.py                # /signature commands (modal, test, preview, pagination)
    poc.py                      # /poc commands
    dict.py                     # /dict commands
    target.py                   # /target commands (scan inputs, masscan import)
    common.py                   # Shared utilities (PaginatedView, ConfirmView, safe_send)
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
        http_prober.py          # HTTP: root page, headers, concurrent endpoint probes
        https_prober.py         # HTTPS: same + SSL cert extraction (async)
        rtsp_prober.py          # RTSP: DESCRIBE on signature paths
        onvif_prober.py         # ONVIF: SOAP GetDeviceInformation
        favicon_prober.py       # Favicon MMH3 hash (reused sessions)
        types.py                # CollectedData model
        base.py                 # Prober ABC with close()
  pipeline/
    builder.py                  # Pipeline construction + lifecycle
  storage/
    base.py                     # StorageBackend interface
    sqlite_backend.py           # SQLite implementation
    schemas.py                  # Pydantic models (Fingerprint, EvidenceItem, etc.)
  utils/
    network.py                  # IP counting, CIDR/range parsing, target classification
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
- Masscan import mode runs Layer 2 only — no masscan subprocess, no root required
- `/scan pause` waits for the full pipeline to stop before responding so the user knows it's safe to modify targets
