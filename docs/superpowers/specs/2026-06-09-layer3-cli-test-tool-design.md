# Layer 3 CLI Test Tool — Design Specification

**Date:** 2026-06-09
**Version:** 1.0
**Purpose:** Local testing interface for Layer 3 CVE search before deploying to Discord bot

---

## 1. Overview

CLI tool with 4 subcommands for testing all Layer 3 components: database enrichment, end-to-end scanning, NVD API queries, and msfrpcd connectivity. Uses `argparse` with zero new dependencies. Output as formatted terminal tables.

## 2. Entry points

```
python3 -m src.cli <command> [options]
python3 -m src                    # delegates to cli.py
```

**Files:**
- Create: `src/cli.py` — argparse + subcommands + output formatting
- Create: `src/__main__.py` — delegates to `src.cli`

## 3. Subcommands

### 3.1 test-db — Layer 3 trên DB đã có

```bash
python3 -m src.cli test-db [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | from config | Path to SQLite database |
| `--limit` | None | Limit number of targets to process |
| `--vendor` | None | Filter by vendor |

**Flow:**
1. Open SQLite DB
2. Read fingerprints table
3. Filter by vendor if specified
4. Apply limit
5. For each target: run classify_exploitability + classify_impact
6. Display table + summary

**Output:**
```
Layer 3 CVE Search — test-db
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IP               Port  Vendor      Model          CVEs              Status
─────────────────────────────────────────────────────────────────────────────
192.168.1.1      80    hikvision   DS-2CD2142     CVE-2021-36260    🔴 RCE
192.168.1.5      80    hikvision   DS-2CD2142     CVE-2017-7921     🟠 Auth bypass
192.168.1.10     554   dahua       DH-IPC-HDW     CVE-2021-33044    🔴 Auth bypass
192.168.1.20     80    hikvision   Unknown        —                 🟡 Unclear
192.168.1.30     80    —           —              —                 ⚪ No result

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 5 targets | 🔴 2 exploitable | 🟠 1 affected | 🟡 1 unclear | ⚪ 1 no result
```

### 3.2 test-scan — End-to-end scan

```bash
python3 -m src.cli test-scan <target> [options]
```

| Argument/Option | Default | Description |
|----------------|---------|-------------|
| `target` | required | IP or CIDR (e.g., `10.0.0.0/24`) |
| `--port` | `80,554,8080,8443` | Ports to scan |
| `--rate` | `1000` | Masscan rate |

**Flow:**
1. Run masscan on target → get open ports
2. Run fingerprinter on each (ip, port)
3. Run Layer 3 CVE search on each fingerprint
4. Display table + summary

### 3.3 test-nvd — Query NVD API

```bash
python3 -m src.cli test-nvd <query> [options]
```

| Argument/Option | Default | Description |
|----------------|---------|-------------|
| `query` | required | CVE ID (e.g., `CVE-2021-36260`) or keyword (e.g., `hikvision`) |
| `--api-key` | from config | Override NVD API key |

**Flow:**
1. If query starts with `CVE-`: lookup by CVE ID via `nvd_client.enrich()`
2. Otherwise: keyword search via `nvd_client.search()`
3. Display results

**Output (CVE lookup):**
```
CVE-2021-36260
  Severity:  CRITICAL (CVSS 9.8)
  Impact:    RCE (Command Injection)
  CWE:       CWE-78
  Description:
    A command injection vulnerability in the web server of some
    Hikvision products...
```

**Output (keyword search):**
```
NVD search: "hikvision" — 12 results

CVE ID              Severity  CVSS   Description
─────────────────────────────────────────────────────────────────────
CVE-2021-36260      CRITICAL  9.8    Command injection in web server...
CVE-2017-7921       HIGH      7.2    Improper authentication...
CVE-2021-33044      HIGH      7.4    Identity authentication bypass...
...
```

### 3.4 test-msf — Test msfrpcd connection

```bash
python3 -m src.cli test-msf [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--password` | from config | msfrpcd password |
| `--host` | `127.0.0.1` | msfrpcd host |
| `--port` | `55553` | msfrpcd port |
| `--search` | None | Search modules for vendor |

**Flow (no --search):**
1. Connect to msfrpcd
2. Report connection status
3. Done

**Flow (with --search):**
1. Connect to msfrpcd
2. Search modules for vendor keyword
3. Display module list with CVE refs

**Output:**
```
msfrpcd: 127.0.0.1:55553 ✓ Connected

Modules for 'hikvision' (3 found):
  exploit/linux/http/hikvision_cmd_injection     CVEs: CVE-2021-36260
  auxiliary/scanner/http/hikvision_default_creds  CVEs: CVE-2017-7921
  auxiliary/scanner/http/hikvision_version         CVEs: (none)
```

## 4. Implementation

### 4.1 src/cli.py structure

```python
"""CLI test tool for Layer 3 CVE search."""
import argparse
import asyncio

def main():
    parser = argparse.ArgumentParser(...)
    subparsers = parser.add_subparsers(...)

    # test-db
    p_db = subparsers.add_parser("test-db", ...)
    p_db.add_argument("--db", ...)
    p_db.add_argument("--limit", ...)
    p_db.add_argument("--vendor", ...)
    p_db.set_defaults(func=cmd_test_db)

    # test-scan
    p_scan = subparsers.add_parser("test-scan", ...)
    p_scan.add_argument("target", ...)
    p_scan.add_argument("--port", ...)
    p_scan.set_defaults(func=cmd_test_scan)

    # test-nvd
    p_nvd = subparsers.add_parser("test-nvd", ...)
    p_nvd.add_argument("query", ...)
    p_nvd.set_defaults(func=cmd_test_nvd)

    # test-msf
    p_msf = subparsers.add_parser("test-msf", ...)
    p_msf.add_argument("--search", ...)
    p_msf.set_defaults(func=cmd_test_msf)

    args = parser.parse_args()
    if hasattr(args, "func"):
        asyncio.run(args.func(args))
    else:
        parser.print_help()

async def cmd_test_db(args): ...
async def cmd_test_scan(args): ...
async def cmd_test_nvd(args): ...
async def cmd_test_msf(args): ...
```

### 4.2 src/__main__.py

```python
from src.cli import main
main()
```

## 5. Output formatting

Plain text — no new dependencies. Uses Unicode box-drawing characters for tables.

```python
# Table formatting helpers
SEPARATOR = "─" * 80
HEADER = "━" * 80

def print_table(headers, rows, widths):
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print(SEPARATOR[:len(header_line)])
    for row in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))

def print_summary(counts):
    parts = [f"{emoji} {count} {label}" for emoji, count, label in counts]
    print(f"Summary: {' | '.join(parts)}")
```

## 6. Error handling

- DB not found → print error + exit 1
- msfrpcd not reachable → print connection error + exit 1
- NVD rate limit → print warning, continue with cached results
- No fingerprints in DB → print "No fingerprints found" + exit 0

## 7. No new dependencies

| Dependency | Status |
|-----------|--------|
| argparse | stdlib |
| asyncio | stdlib |
| sqlite3 | stdlib |
| json | stdlib |
| Existing project modules | NVDClient, MSFRPCClient, CVESearcher, classifier, config, storage |
