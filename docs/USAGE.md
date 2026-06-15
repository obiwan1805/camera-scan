# Discord Bot Usage Guide

This document covers every Discord command, common workflows, and tips for using the camera scanner bot.

Every command group has a `/<group> help` command that shows in-Discord help. This document is the offline reference.

---

## Table of Contents

1. [General Help](#general-help)
2. [Scan Controls (`/scan`)](#scan-controls-scan)
3. [Targets (`/target`)](#targets-target)
4. [Runtime Config (`/config`)](#runtime-config-config)
5. [Signatures (`/signature`)](#signatures-signature)
6. [PoC Scripts (`/poc`)](#poc-scripts-poc)
7. [Password Dictionaries (`/dict`)](#password-dictionaries-dict)
8. [Common Workflows](#common-workflows)

---

## General Help

There is no global `/help` command. Instead, each command group has its own help:

| Command | What it shows |
|---------|--------------|
| `/scan help` | Scan control commands (start, pause, stop, progress) |
| `/target help` | Target management commands (add, remove, list, import, import-masscan) |
| `/config help` | Runtime configuration commands (scan_rate, timeouts, concurrency) |
| `/signature help` | Signature management commands (list, show, test, add, remove, export, import, reload) |
| `/poc help` | PoC script commands (add, remove, list, show) |
| `/dict help` | Dictionary commands (add, remove, import, show, list) |

Type any of these in Discord to see the full reference for that group.

---

## Scan Controls (`/scan`)

The core scan pipeline. Layer 1 (masscan) discovers open ports, Layer 2 (fingerprinter) identifies devices.

### Commands

| Command | Description |
|---------|-------------|
| `/scan start` | Start or resume the scan. Requires targets or a staged masscan import. |
| `/scan pause` | Pause the scan. Masscan writes `paused.conf` so it can resume. Waits for full pipeline stop. |
| `/scan stop` | Stop the scan and delete `paused.conf`. Results are saved but the scan restarts from scratch next time. |
| `/scan progress` | Live stats: IPs scanned, discovered, fingerprinted, queue depth, processing rate. |

### Rules

- Cannot start if a scan is already running.
- Cannot start with no targets and no staged import (unless resuming from `paused.conf`).
- `/scan pause` and `/scan stop` only work when a scan is running.

### What `/scan start` does

1. Checks if `data/masscan_import.txt` exists and no `paused.conf` — if so, runs **Layer 2 only** (fingerprinter feeds from the imported file).
2. Otherwise, runs the full **Layer 1 + Layer 2** pipeline using targets from the DB.
3. If `paused.conf` exists, masscan resumes from where it left off.

---

## Targets (`/target`)

Scan inputs — the IP addresses, CIDR ranges, and IP ranges that masscan will sweep.

### Commands

| Command | Description |
|---------|-------------|
| `/target add <target>` | Add an IP, CIDR, or IP range. e.g. `192.168.1.0/24`, `10.0.0.1`, `1.0.0.0-1.0.255.255` |
| `/target remove <id>` | Remove a target by ID (shown in `/target list`) |
| `/target list [type]` | List all targets with pagination. Optional filter: `cidr`, `ip`, `range`. Works during a scan. |
| `/target import <file>` | Bulk import targets from a text file (one per line). Shows total IP count. |
| `/target export` | Export targets to `data/cidrs.txt`. Works anytime. |
| `/target clear` | Remove ALL targets (with confirmation prompt). Also deletes `paused.conf`. |
| `/target import-masscan <file>` | Stage masscan `-oL` output for standalone fingerprinting (Layer 2 only). |

### Rules

- All target commands (except `list` and `export`) require the scan to be idle.
- `/target list` works during a scan — useful for checking what's being scanned.

### Examples

```
/target add 192.168.1.0/24
→ Added 192.168.1.0/24 (cidr) — id=1, total=1 targets, 256 IPs

/target add 10.0.0.1
→ Added 10.0.0.1 (ip) — id=2, total=2 targets, 257 IPs

/target list
→ Shows all targets with IDs, types, and IP counts
```

### Masscan import mode

If you already have masscan output (from a previous scan, or from running masscan separately), you can feed it directly to the fingerprinter without re-scanning:

```
/target import-masscan results.txt
→ Imported 1,234 hosts, 2,000 entries. Use /scan start to begin fingerprinting.

/scan start
→ Runs Layer 2 only (no masscan subprocess, no root required)
```

The import file format is masscan's `-oL` format:

```
open tcp 80 192.168.1.100 1700000000
open tcp 554 192.168.1.100 1700000000
open tcp 80 192.168.1.101 1700000000
# Masscan done
```

---

## Runtime Config (`/config`)

All parameters can be changed at runtime and are **persisted to `config/default.yaml`** — changes survive bot restarts.

### Commands

| Command | Default | Description |
|---------|---------|-------------|
| `/config show` | — | Display all current values |
| `/config scan_rate <n>` | 1,000 | Masscan packets per second. Higher = faster but noisier. |
| `/config masscan_wait <n>` | 10 | Seconds masscan waits per probe for a response (1-300). |
| `/config max_concurrent <n>` | 200 | Max concurrent fingerprinter probes. |
| `/config prober_timeout <n>` | 10 | Timeout per prober request in seconds (1-60). |
| `/config import_feed_batch <n>` | 100 | Entries per batch during masscan import (1-10,000). |
| `/config import_feed_interval <n>` | 5 | Seconds between feed batches during import (1-300). |

### Rules

- All `/config` setters require the scan to be idle.
- Changes apply on the **next** `/scan start`, not to a running scan.

### Tuning tips

- **Fast scanning, lots of bandwidth**: `scan_rate` 10000+, `max_concurrent` 500+
- **Slow/stealthy**: `scan_rate` 100-500, `max_concurrent` 50
- **Slow network, catching more hosts**: increase `masscan_wait` to 30-60
- **Importing huge masscan files**: lower `import_feed_batch` to 20-50 to reduce DB pressure

---

## Signatures (`/signature`)

Signatures are the heart of the fingerprinter — they define how to identify vendors, models, and versions from collected data. See **[SIGNATURES.md](SIGNATURES.md)** for the full guide on writing and managing signatures.

### Commands

| Command | Description |
|---------|-------------|
| `/signature list [vendor]` | List signature counts for a vendor (dropdown if no vendor given). |
| `/signature show <vendor> [pattern_type]` | Show pattern previews. With `pattern_type`, shows full details paginated. |
| `/signature test` | Opens a modal to test a regex against sample text before adding. |
| `/signature add` | Opens a modal form to add a new signature pattern. |
| `/signature remove <vendor> <pattern_type> <index>` | Remove a specific pattern by index. |
| `/signature export <vendor>` | Download a vendor's YAML file as an attachment. |
| `/signature import <file>` | Import a vendor YAML file. |
| `/signature reload` | Force reload all signatures from disk. |

All signature commands work anytime — even during a running scan. Changes hot-reload automatically every 30 seconds.

### Pattern types

| Type | What it matches | Example |
|------|----------------|---------|
| `brand_keyword` | Plain string in HTML/headers/banner | `hikvision` |
| `model` | Regex with optional capture group for model extraction | `DS-2CD\d+[A-Za-z\d-]*` |
| `version` | Regex with optional normalization | `<firmwareVersion>(.*?)</firmwareVersion>` |
| `favicon_hash` | Integer MMH3 hash | `999357577` |
| `endpoint` | HTTP path that feeds XML/JSON into the matcher | `/ISAPI/System/deviceInfo` |
| `onvif` | ONVIF manufacturer match + model/firmware extraction | manufacturer: `hikvision` |
| `rtsp_path` | RTSP URL that feeds banner data | `/h264/ch1/main/av_stream` |
| `extra` | Extensible patterns (e.g. SSL CN matching) | type: `ssl_cn` |

### Recommended workflow for adding signatures

1. **Test first**: Use `/signature test` to verify your regex matches expected input.
2. **Add via modal**: Use `/signature add` — it opens a form with a preview and test button.
3. **Verify**: Use `/signature show <vendor> <pattern_type>` to confirm it was added.
4. **Export backup**: Use `/signature export <vendor>` to download the YAML.

See **[SIGNATURES.md](SIGNATURES.md)** for detailed examples.

---

## PoC Scripts (`/poc`)

Store proof-of-concept exploit scripts linked to CVEs and vendors.

### Commands

| Command | Description |
|---------|-------------|
| `/poc list [vendor]` | List all PoCs, optionally filtered by vendor. |
| `/poc add <name> [options]` | Add a PoC via file upload or `script_content` text. |
| `/poc show <id>` | Show full PoC details including script content. |
| `/poc remove <id>` | Remove a PoC by ID. |

### `/poc add` options

| Option | Required | Description |
|--------|----------|-------------|
| `name` | Yes | Script name |
| `file` | One of file/script_content | Upload script file |
| `script_content` | One of file/script_content | Or paste script code |
| `cve_id` | No | e.g. `CVE-2021-36260` |
| `vendor` | No | Target vendor |
| `protocol` | No | `http`, `rtsp`, `onvif`, etc. |
| `script_type` | No | `python`, `bash`, `powershell` (default: python) |
| `description` | No | What it does |
| `severity` | No | `critical`, `high`, `medium`, `low` |

All PoC commands work anytime.

---

## Password Dictionaries (`/dict`)

Manage credential dictionaries for brute-force testing.

### Commands

| Command | Description |
|---------|-------------|
| `/dict list` | List all dictionary types with counts. |
| `/dict add <dict_type> <value>` | Add a single entry. |
| `/dict import <dict_type> <file>` | Bulk import from text file (one per line). |
| `/dict show <dict_type>` | Show all entries with IDs. |
| `/dict remove <id>` | Remove entry by ID. |

### Dictionary types

You can use any name. Common ones:

- `default_usernames` — e.g. `admin`, `root`, `service`
- `default_passwords` — e.g. `admin123`, `12345`, `hik12345`
- `default_creds` — user:pass pairs, e.g. `admin:admin`

All dict commands work anytime.

---

## Common Workflows

### Workflow 1: Fresh scan with CIDR target

```
/target add 192.168.1.0/24
/config scan_rate 5000
/scan start
/scan progress
/scan progress
/scan progress
(scan completes automatically)
```

### Workflow 2: Import and fingerprint existing masscan output

```
/target import-masscan masscan_results.txt
→ Imported 5,000 hosts, 8,000 entries.

/config import_feed_batch 50
/config import_feed_interval 5
/scan start
→ Runs Layer 2 only
```

### Workflow 3: Pause and resume later

```
/scan start
(scanning...)
/scan pause
→ Pipeline fully stopped. Masscan wrote paused.conf.

(later...)
/scan start
→ Resumes from paused.conf
```

### Workflow 4: Stop completely (fresh start next time)

```
/scan stop
→ Deletes paused.conf. Next /scan start begins from scratch.
```

### Workflow 5: Add a new vendor signature during a scan

```
/signature add
→ Opens modal. Enter vendor, type, pattern, CVEs.
→ Signatures hot-reload within 30 seconds. No restart needed.
```

### Workflow 6: Tune for slow networks

```
/config scan_rate 500
/config masscan_wait 30
/config prober_timeout 20
/config max_concurrent 50
/scan start
```

---

## Status Indicators

The bot tracks scan status:

- **idle** — No scan running. All config/target commands work.
- **running** — Scan in progress. Only `/scan pause`, `/scan stop`, `/scan progress`, and read-only commands work.
- **stopping** — Scan is shutting down. Wait for it to return to idle.

---

## Troubleshooting

### "Cannot change config while scan is running"
Use `/scan pause` or `/scan stop` first, then change config.

### "No targets configured"
Add a target with `/target add` or stage a masscan import with `/target import-masscan`.

### "Previous scan is still shutting down, please wait..."
The pipeline is tearing down. Wait a few seconds and try again.

### Commands not appearing in Discord
If you didn't set `DISCORD_GUILD_ID`, commands sync globally which can take up to an hour. Restart the bot or set the guild ID.

### Masscan permission denied
Run the bot with `sudo -E python3 bot.py`. Masscan needs raw socket access.

### Database locked errors during masscan import
Lower `import_feed_batch` (e.g. to 20-50) and increase `import_feed_interval` (e.g. to 10s).
