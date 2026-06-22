# CLI Usage — `main.py`

`main.py` is a thin shell interface for managing scan targets without Discord. It writes to the same SQLite database the bot uses (`data/camera_scan.db`), so anything staged from the shell is picked up by the next `/scan start` in Discord.

The CLI only covers target management — it does **not** start scans, change config, or manage signatures/PoCs/dicts. For those, use the Discord bot (see [USAGE.md](USAGE.md)).

## Why use the CLI

- **Scripting** — bulk-prepare targets in cron jobs or shell pipelines
- **No Discord round-trip** — paste in a terminal, instant feedback
- **Masscan output staging** — drop a results file in place without uploading to Discord

## Subcommands

### `add <target>`

Add a single target. Mirrors `/target add`.

```bash
python3 main.py add 192.168.1.0/24
python3 main.py add 10.0.0.1
python3 main.py add 1.0.0.0-1.0.255.255
```

Output: `Added 192.168.1.0/24 (cidr) — id=1, total=1 targets, 256 IPs`

Validates format before inserting. Refuses duplicates.

### `list [--type cidr|ip|range]`

Print all targets as a table. Mirrors `/target list`.

```bash
python3 main.py list
python3 main.py list --type cidr
```

Output:

```
  ID  TYPE    IPS  TARGET
   1  cidr     256  192.168.1.0/24
   2  ip         1  10.0.0.1
   3  range  65536  1.0.0.0-1.0.255.255

3 targets, 65,793 IPs total
```

### `remove <id> [--cascade]`

Delete one target by ID. Mirrors `/target remove`.

```bash
python3 main.py remove 5                 # target row only
python3 main.py remove 5 --cascade       # also wipe matching result rows
```

`--cascade` calls `clear_target_results(spec)` which deletes any `port_scans`, `fingerprints`, `raw_responses`, and `claims` rows whose IP falls inside the target's range. Equivalent to the bot's **Remove all** button. Without `--cascade`, only the `targets` row is removed — equivalent to **Target only**.

### `import <file>`

Bulk add targets from a text file. Mirrors `/target import`.

```bash
python3 main.py import targets.txt
```

Format: one entry per line. `#` starts a comment. Blank lines are skipped.

```
# targets.txt — sample
192.168.1.0/24
10.0.0.0/16
8.8.8.8
1.0.0.0-1.0.0.255
```

Duplicates and malformed lines are skipped with a per-line message; the final summary reports the count:

```
  skip duplicate: 192.168.1.0/24
Imported 3 targets (65,792 IPs) (1 duplicates/errors skipped)
```

### `import-masscan <file>`

Stage masscan `-oL` output for the next `/scan start`. Mirrors `/target import-masscan`.

```bash
python3 main.py import-masscan results.txt
```

Parses the file using the same `parse_masscan_line` logic as the live scanner, reports host/entry counts, and copies the file to `data/masscan_import.txt`:

```
Staged 2,000 hosts, 3,500 entries → data/masscan_import.txt
Use the bot's /scan start to begin fingerprinting (Layer 2 only).
```

When the bot's `/scan start` sees `data/masscan_import.txt` and no `paused.conf`, it runs the fingerprinter only — no masscan subprocess, no root required.

Input format (masscan `-oL`):

```
open tcp 80 192.168.1.100 1700000000
open tcp 554 192.168.1.100 1700000000
# Masscan done
```

If the file has no `open tcp` lines, the staging is aborted and `data/masscan_import.txt` is not written.

### `clear [--yes]`

Remove ALL targets. Mirrors the **Just delete** path of `/target clear`.

```bash
python3 main.py clear           # prompts for confirmation
python3 main.py clear --yes     # skip prompt
```

**Important:** `clear` only wipes the `targets` table. It does NOT touch `port_scans`, `fingerprints`, `raw_responses`, `claims`, `paused.conf`, or scan files. For a full reset including results, use the Discord bot's `/target clear` with the **Export then delete** or **Just delete** button — the CLI deliberately leaves results alone so you don't accidentally destroy scan data from a shell script.

## Shared state with the bot

The CLI and the bot share `data/camera_scan.db`. Practical implications:

- Targets added via CLI are visible in `/target list` immediately
- Targets removed via CLI disappear from the next `/scan start`
- The bot must be idle for the changes to affect scans (the bot's `_check_idle` rule still applies)
- If both the CLI and the bot are writing at the same time, SQLite's WAL mode handles concurrent reads; concurrent writes from the bot's pipeline could briefly block CLI writes

## Examples

### Bulk prep from a CIDR list

```bash
$ cat my_targets.txt
192.168.1.0/24
10.0.0.0/16

$ python3 main.py import my_targets.txt
Imported 2 targets (65,792 IPs)

$ python3 main.py list
  ID  TYPE    IPS  TARGET
   1  cidr     256  192.168.1.0/24
   2  cidr  65536  10.0.0.0/16

2 targets, 65,792 IPs total
```

Now in Discord: `/scan start`.

### Stage masscan output without scanning again

```bash
$ masscan -p80,554 -oL results.txt --rate 10000 192.168.1.0/24
[scan completes]

$ python3 main.py import-masscan results.txt
Staged 47 hosts, 89 entries → data/masscan_import.txt
Use the bot's /scan start to begin fingerprinting (Layer 2 only).
```

Now in Discord: `/scan start` runs the fingerprinter against the staged file.

### Remove a target and its results

```bash
$ python3 main.py list
  ID  TYPE    IPS  TARGET
   1  cidr     256  192.168.1.0/24

$ python3 main.py remove 1 --cascade
Removed target id=1 (192.168.1.0/24). Also deleted 47 result rows: 47 port scans, 12 fingerprints, 0 raw responses, 0 claims.
```
