"""Camera-scan target management CLI.

Thin shell interface to the `targets` table — mirrors the `/target` Discord
commands. Writes to the same SQLite DB the bot reads, so anything staged here
is picked up by the next `/scan start`.

Subcommands:
    add <target>                Add one IP/CIDR/range
    list [--type T]             List targets
    remove <id> [--cascade]     Remove target by ID (optionally its results)
    import <file>               Bulk import from text file
    import-masscan <file>       Stage masscan -oL output for /scan start
    clear [--yes]               Wipe all targets
"""
import argparse
import asyncio
import sys
from pathlib import Path

from src.storage.sqlite_backend import SQLiteBackend
from src.utils.network import (
    classify_target,
    count_ips_in_cidr,
    count_ips_in_range,
)
from src.layers import PortScanner


def _ip_count(target: str, target_type: str) -> int:
    if target_type == "range":
        return count_ips_in_range(target)
    return count_ips_in_cidr(target)


def _validate_target(target: str, target_type: str) -> str | None:
    """Return None if valid, else an error message."""
    import ipaddress

    if target_type == "cidr":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            return f"invalid CIDR: {target}"
    elif target_type == "ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return f"invalid IP: {target}"
    elif target_type == "range":
        parts = target.split("-")
        if len(parts) != 2:
            return f"invalid range: {target}"
        try:
            ipaddress.ip_address(parts[0].strip())
            ipaddress.ip_address(parts[1].strip())
        except ValueError:
            return f"invalid range: {target}"
    return None


async def cmd_add(args):
    target = args.target.strip()
    target_type = classify_target(target)

    err = _validate_target(target, target_type)
    if err:
        print(f"Error: {err}")
        return 1

    db = SQLiteBackend()
    await db.connect()
    try:
        try:
            row_id = await db.generic_insert("targets", {"target": target, "type": target_type})
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                print(f"Target {target} already exists.")
                return 1
            raise
        rows = await db.generic_list("targets")
        total_ips = sum(_ip_count(r["target"], r["type"]) for r in rows)
        print(
            f"Added {target} ({target_type}) — id={row_id}, "
            f"total={len(rows)} targets, {total_ips:,} IPs"
        )
    finally:
        await db.disconnect()


async def cmd_list(args):
    db = SQLiteBackend()
    await db.connect()
    try:
        filters = {"type": args.type} if args.type else None
        rows = await db.generic_list("targets", filters)
        if not rows:
            print("No targets configured.")
            return

        print(f"{'ID':>4}  {'TYPE':<6}  {'IPS':>10}  TARGET")
        for r in rows:
            print(
                f"{r['id']:>4}  {r['type']:<6}  "
                f"{_ip_count(r['target'], r['type']):>10,}  {r['target']}"
            )
        total_ips = sum(_ip_count(r["target"], r["type"]) for r in rows)
        print(f"\n{len(rows)} targets, {total_ips:,} IPs total")
    finally:
        await db.disconnect()


async def cmd_remove(args):
    db = SQLiteBackend()
    await db.connect()
    try:
        rows = await db.generic_list("targets")
        target_row = next((r for r in rows if r["id"] == args.id), None)
        if not target_row:
            print(f"Target id={args.id} not found.")
            return 1

        deleted = await db.generic_delete("targets", args.id)
        if not deleted:
            print(f"Target id={args.id} not found.")
            return 1

        if args.cascade:
            counts = await db.clear_target_results(target_row["target"])
            total = sum(counts.values())
            print(
                f"Removed target id={args.id} ({target_row['target']}). "
                f"Also deleted {total} result rows: "
                f"{counts.get('port_scans', 0)} port scans, "
                f"{counts.get('fingerprints', 0)} fingerprints, "
                f"{counts.get('raw_responses', 0)} raw responses, "
                f"{counts.get('claims', 0)} claims."
            )
        else:
            print(f"Removed target id={args.id} ({target_row['target']}). Result rows left intact.")
    finally:
        await db.disconnect()


async def cmd_import(args):
    src = Path(args.file)
    if not src.exists():
        print(f"Error: file not found: {src}")
        return 1

    text = src.read_text(encoding="utf-8-sig")
    db = SQLiteBackend()
    await db.connect()
    try:
        added = 0
        errors = 0
        total_ips = 0
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            target_type = classify_target(entry)
            err = _validate_target(entry, target_type)
            if err:
                print(f"  skip: {err}")
                errors += 1
                continue
            try:
                await db.generic_insert("targets", {"target": entry, "type": target_type})
                added += 1
                total_ips += _ip_count(entry, target_type)
            except Exception as e:
                if "UNIQUE constraint" in str(e):
                    print(f"  skip duplicate: {entry}")
                else:
                    print(f"  skip error: {entry} ({e})")
                errors += 1

        msg = f"Imported {added} targets ({total_ips:,} IPs)"
        if errors:
            msg += f" ({errors} duplicates/errors skipped)"
        print(msg)
    finally:
        await db.disconnect()


async def cmd_import_masscan(args):
    src = Path(args.file)
    if not src.exists():
        print(f"Error: file not found: {src}")
        return 1

    text = src.read_text(encoding="utf-8-sig", errors="ignore")
    hosts: set[str] = set()
    count = 0
    for line in text.splitlines():
        result = PortScanner.parse_masscan_line(line)
        if result:
            hosts.add(result[0])
            count += 1

    if count == 0:
        print("No valid 'open tcp' entries found in file.")
        return 1

    Path("data").mkdir(exist_ok=True)
    Path("data/masscan_import.txt").write_bytes(src.read_bytes())
    print(
        f"Staged {len(hosts):,} hosts, {count:,} entries → data/masscan_import.txt\n"
        f"Use the bot's /scan start to begin fingerprinting (Layer 2 only)."
    )


async def cmd_clear(args):
    db = SQLiteBackend()
    await db.connect()
    try:
        rows = await db.generic_list("targets")
        if not rows:
            print("No targets to clear.")
            return

        if not args.yes:
            confirm = input(f"Delete all {len(rows)} targets? [y/N] ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                return

        for r in rows:
            await db.generic_delete("targets", r["id"])
        print(f"Cleared {len(rows)} targets. Result rows left intact.")
    finally:
        await db.disconnect()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Camera-scan target management CLI (mirrors /target Discord commands)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="Add a single target (IP, CIDR, or range)")
    a.add_argument("target")
    a.set_defaults(func=cmd_add)

    l = sub.add_parser("list", help="List all targets")
    l.add_argument("--type", choices=["cidr", "ip", "range"], help="Filter by type")
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("remove", help="Remove a target by ID")
    r.add_argument("id", type=int)
    r.add_argument(
        "--cascade",
        action="store_true",
        help="Also delete matching port_scans/fingerprints/raw_responses/claims",
    )
    r.set_defaults(func=cmd_remove)

    i = sub.add_parser("import", help="Bulk import targets from a text file")
    i.add_argument("file")
    i.set_defaults(func=cmd_import)

    im = sub.add_parser("import-masscan", help="Stage masscan -oL output for /scan start")
    im.add_argument("file")
    im.set_defaults(func=cmd_import_masscan)

    c = sub.add_parser("clear", help="Remove ALL targets (result rows are left intact)")
    c.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    c.set_defaults(func=cmd_clear)

    return p


def main():
    args = build_parser().parse_args()
    rc = asyncio.run(args.func(args))
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
