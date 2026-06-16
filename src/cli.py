"""CLI test tool for Layer 3 CVE search.

Usage:
    python3 -m src.cli test-db [--db PATH] [--limit N] [--vendor NAME]
    python3 -m src.cli test-scan <target> [--port PORTS] [--rate RATE]
    python3 -m src.cli test-nvd <query> [--api-key KEY]
    python3 -m src.cli test-msf [--password PW] [--host HOST] [--port PORT] [--search VENDOR]
"""
import argparse
import asyncio
import json
import sys

from src.core.config import Config, get_default_config
from src.storage.schemas import Fingerprint, CameraFingerprint
from src.utils.logging import setup_logger

logger = setup_logger("CLI")

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

SEPARATOR = "─" * 100
HEADER_BAR = "━" * 100


def _print_table(headers, rows, widths):
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print()
    print(header_line)
    print(SEPARATOR[: len(header_line)])
    for row in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))
    print()


def _print_summary(total, exploitable, affected, unclear, no_result):
    parts = []
    if exploitable:
        parts.append(f"🔴 {exploitable} exploitable")
    if affected:
        parts.append(f"🟠 {affected} affected")
    if unclear:
        parts.append(f"🟡 {unclear} unclear")
    if no_result:
        parts.append(f"⚪ {no_result} no result")
    print(f"Summary: {total} targets | {' | '.join(parts)}")


# ---------------------------------------------------------------------------
# test-db: classify existing fingerprints from SQLite
# ---------------------------------------------------------------------------


async def cmd_test_db(args):
    """Run classification on existing fingerprints in the database."""
    from src.storage.sqlite_backend import SQLiteBackend
    from src.layers.layer3_cve_searcher.classifier import (
        classify_exploitability,
        classify_impact,
        STATUS_EMOJI,
        IMPACT_LABELS,
    )

    config = _load_config()
    db_path = args.db or config.storage.path
    print(f"Layer 3 CVE Search — test-db")
    print(f"Database: {db_path}")
    print(HEADER_BAR)

    storage = SQLiteBackend(db_path)
    await storage.connect()

    # Read fingerprints
    try:
        rows = await storage._conn.execute_fetchall(
            "SELECT ip, port, fingerprint, weight FROM fingerprints"
        )
    except Exception as e:
        print(f"Error reading database: {e}")
        await storage.disconnect()
        return

    if not rows:
        print("No fingerprints found in database.")
        await storage.disconnect()
        return

    # Parse
    items = []
    for ip, port, fp_json, weight in rows:
        try:
            fp_data = json.loads(fp_json) if isinstance(fp_json, str) else fp_json
            fp = Fingerprint(**fp_data)
            items.append((ip, port, fp, weight or 0.0))
        except Exception:
            items.append((ip, port, Fingerprint(), 0.0))

    # Filter
    if args.vendor:
        vendor_lower = args.vendor.lower()
        items = [(ip, port, fp, w) for ip, port, fp, w in items
                 if fp.vendor and fp.vendor.lower() == vendor_lower]
        print(f"Filtered by vendor: {args.vendor} ({len(items)} targets)")

    if args.limit:
        items = items[: args.limit]
        print(f"Limited to {args.limit} targets")

    if not items:
        print("No matching fingerprints.")
        await storage.disconnect()
        return

    # Read PoCs for classification
    try:
        poc_rows = await storage._conn.execute_fetchall("SELECT name, data FROM pocs")
        all_pocs = {}
        for name, data in poc_rows:
            try:
                all_pocs[name] = json.loads(data) if isinstance(data, str) else data
            except Exception:
                pass
    except Exception:
        all_pocs = {}

    # Classify and display
    headers = ["IP", "Port", "Vendor", "Model", "CVEs", "Status"]
    widths = [18, 6, 12, 16, 30, 18]
    rows_out = []

    counts = {"exploitable": 0, "affected": 0, "unclear": 0, "no_result": 0}

    for ip, port, fp, weight in items:
        # Find PoCs for this target's CVEs
        pocs_for_target = []
        for poc_data in all_pocs.values():
            if poc_data.get("cve_id") in fp.cves:
                from src.storage.schemas import PoC
                pocs_for_target.append(PoC(
                    name=poc_data.get("name", ""),
                    cve_id=poc_data.get("cve_id"),
                    script_content=poc_data.get("script_content"),
                ))

        status = classify_exploitability(fp, pocs_for_target)

        # Get impact for first CVE
        impact_str = "—"
        if fp.cves:
            impacts = set()
            for cve_id in fp.cves:
                poc = next((p for p in all_pocs.values() if p.get("cve_id") == cve_id), None)
                desc = poc.get("description", "") if poc else ""
                imp = classify_impact(desc, "", "", "")
                impacts.update(imp)
            impact_str = ", ".join(IMPACT_LABELS.get(i, i) for i in impacts if i != "unknown") or "—"

        cves_str = ", ".join(fp.cves[:3]) if fp.cves else "—"
        if len(fp.cves) > 3:
            cves_str += f" +{len(fp.cves)-3}"

        emoji = STATUS_EMOJI.get(status, "⚪")
        status_str = f"{emoji} {impact_str}" if status != "no_result" else "⚪ —"

        rows_out.append([
            ip, str(port),
            fp.vendor or "—",
            fp.model or "—",
            cves_str,
            status_str,
        ])
        counts[status] += 1

    _print_table(headers, rows_out, widths)
    _print_summary(len(items), counts["exploitable"], counts["affected"],
                   counts["unclear"], counts["no_result"])

    await storage.disconnect()


# ---------------------------------------------------------------------------
# test-scan: end-to-end Layer 1 → 2 → 3
# ---------------------------------------------------------------------------


async def cmd_test_scan(args):
    """Run end-to-end scan: masscan → fingerprint → CVE search."""
    from src.layers.layer1_port_scanner.scanner import PortScanner, CIDRInputSource
    from src.layers.layer2_fingerprinter.fingerprinter import Fingerprinter
    from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
    from src.layers.layer3_cve_searcher.classifier import (
        classify_exploitability,
        STATUS_EMOJI,
        IMPACT_LABELS,
    )
    from src.storage.sqlite_backend import SQLiteBackend
    from src.core.durable_queue import DurableQueue

    config = _load_config()
    target = args.target
    ports = args.port

    print(f"Layer 3 CVE Search — test-scan")
    print(f"Target: {target}")
    print(f"Ports:  {ports}")
    print(HEADER_BAR)

    storage = SQLiteBackend(config.storage.path)
    await storage.connect()

    # Build queues
    queue_0 = _SimpleQueue()
    queue_1 = _SimpleQueue()

    # Layer 1: Port scan
    print("\n[Layer 1] Scanning ports...")
    scanner = PortScanner(config.layer1, queue_0, queue_1, storage)
    source = CIDRInputSource(target, ports=ports)
    await scanner.start(source)

    count_l1 = queue_1.size()
    print(f"[Layer 1] Found {count_l1} open ports")

    # Layer 2: Fingerprint
    print("\n[Layer 2] Fingerprinting...")
    fp = Fingerprinter(config.layer2, queue_1, _SimpleQueue(), storage)
    await fp.start()
    # Wait for completion
    while fp._running:
        await asyncio.sleep(0.5)
        if queue_1.size() == 0 and fp._processing_count == 0:
            break

    count_l2 = fp._processed
    print(f"[Layer 2] Fingerprinted {count_l2} targets")

    # Layer 3: CVE search
    print("\n[Layer 3] Searching CVEs...")
    cve_searcher = CVESearcher(config.layer3, queue_1, None, storage)

    # Read fingerprints from DB for Layer 3
    try:
        rows = await storage._conn.execute_fetchall(
            "SELECT ip, port, fingerprint, weight FROM fingerprints"
        )
    except Exception as e:
        print(f"Error reading fingerprints: {e}")
        await storage.disconnect()
        return

    results = []
    for ip, port, fp_json, weight in rows:
        try:
            fp_data = json.loads(fp_json) if isinstance(fp_json, str) else fp_json
            fp_model = Fingerprint(**fp_data)
            item = CameraFingerprint(ip=ip, port=port, fingerprint=fp_model, weight=weight or 0.0)
            results.append(item)
        except Exception:
            pass

    if not results:
        print("No fingerprints to process.")
        await storage.disconnect()
        return

    # Process through Layer 3
    counts = {"exploitable": 0, "affected": 0, "unclear": 0, "no_result": 0}
    headers = ["IP", "Port", "Vendor", "Model", "CVEs", "Status"]
    widths = [18, 6, 12, 16, 30, 18]
    rows_out = []

    for item in results:
        enriched = await cve_searcher.process(item)
        fp = enriched.fingerprint

        status = classify_exploitability(fp, [])
        emoji = STATUS_EMOJI.get(status, "⚪")

        cves_str = ", ".join(fp.cves[:3]) if fp.cves else "—"
        if len(fp.cves) > 3:
            cves_str += f" +{len(fp.cves)-3}"

        rows_out.append([
            item.ip, str(item.port),
            fp.vendor or "—",
            fp.model or "—",
            cves_str,
            f"{emoji} {status}",
        ])
        counts[status] += 1

    _print_table(headers, rows_out, widths)
    _print_summary(len(results), counts["exploitable"], counts["affected"],
                   counts["unclear"], counts["no_result"])

    # Cleanup
    if cve_searcher._nvd_client:
        await cve_searcher._nvd_client.close()
    if cve_searcher._msf_client:
        try:
            await cve_searcher._msf_client.disconnect()
        except Exception:
            pass
    await storage.disconnect()


# ---------------------------------------------------------------------------
# test-nvd: query NVD API
# ---------------------------------------------------------------------------


async def cmd_test_nvd(args):
    """Query NVD API directly."""
    from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
    from src.layers.layer3_cve_searcher.classifier import classify_impact, IMPACT_LABELS

    config = _load_config()
    nvd_config = config.layer3.nvd
    if args.api_key:
        from src.core.config import NVDConfig
        nvd_config = NVDConfig(api_key=args.api_key)

    client = NVDClient(nvd_config)
    query = args.query

    if query.upper().startswith("CVE-"):
        # Single CVE lookup
        print(f"NVD Lookup: {query}")
        print(HEADER_BAR)
        results = await client.enrich([query])
        if results and results[0].get("severity"):
            r = results[0]
            impacts = classify_impact(r.get("description", ""), "", "", "")
            impact_str = ", ".join(IMPACT_LABELS.get(i, i) for i in impacts)
            print(f"\n  {r['cve_id']}")
            print(f"  Severity:  {r.get('severity', 'N/A')} (CVSS {r.get('cvss_score', 'N/A')})")
            print(f"  Impact:    {impact_str}")
            desc = r.get("description", "")
            if desc:
                # Word wrap description
                print(f"  Description:")
                for line in _wrap_text(desc, width=72, indent=4):
                    print(line)
        else:
            print(f"  No data found for {query}")
    else:
        # Keyword search
        print(f"NVD Search: \"{query}\"")
        print(HEADER_BAR)
        entries = await client.search(query, "", None)
        if not entries:
            print("  No results found.")
        else:
            print(f"\n  {len(entries)} results\n")
            headers = ["CVE ID", "Severity", "CVSS", "Description"]
            widths = [20, 12, 6, 52]
            rows_out = []
            for e in entries:
                desc = (e.description or "")[:50] + ("..." if len(e.description or "") > 50 else "")
                rows_out.append([
                    e.cve_id,
                    e.severity or "N/A",
                    str(e.cvss_score or "N/A"),
                    desc,
                ])
            _print_table(headers, rows_out, widths)

    await client.close()


# ---------------------------------------------------------------------------
# test-msf: test msfrpcd connection + module search
# ---------------------------------------------------------------------------


async def cmd_test_msf(args):
    """Test msfrpcd connection and optionally search modules."""
    from src.core.config import MSFConfig
    from src.layers.layer3_cve_searcher.clients.msf_rpc_client import MSFRPCClient

    config = _load_config()
    msf_config = config.layer3.msf
    if args.password:
        msf_config = MSFConfig(
            host=args.host or msf_config.host,
            port=int(args.port) if args.port else msf_config.port,
            password=args.password,
        )

    client = MSFRPCClient(msf_config)

    # Connect
    print(f"msfrpcd: {msf_config.host}:{msf_config.port}", end=" ")
    try:
        await client.connect()
        print("✓ Connected")
    except Exception as e:
        print(f"✗ Failed: {e}")
        return

    # Module search
    if args.search:
        vendor = args.search
        print(f"\nSearching modules for '{vendor}'...")
        try:
            modules = await client.search_modules(vendor)
        except Exception as e:
            print(f"Search failed: {e}")
            await client.disconnect()
            return

        if not modules:
            print(f"  No modules found for '{vendor}'")
        else:
            print(f"\n  {len(modules)} modules found:\n")
            for m in modules:
                cves = ", ".join(m.get("cves", [])) or "(none)"
                print(f"  {m['name']:<50} CVEs: {cves}")

    await client.disconnect()


# ---------------------------------------------------------------------------
# run-layer3: full CVE search on all fingerprints in DB
# ---------------------------------------------------------------------------


async def cmd_run_layer3(args):
    """Run Layer 3 CVE search on all fingerprints in the database."""
    from src.storage.sqlite_backend import SQLiteBackend
    from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
    from src.layers.layer3_cve_searcher.classifier import (
        classify_exploitability,
        STATUS_EMOJI,
    )
    from src.core.durable_queue import DurableQueue

    config = _load_config()
    db_path = args.db or config.storage.path

    print(f"Layer 3 CVE Search — run-layer3")
    print(f"Database: {db_path}")
    print(HEADER_BAR)

    storage = SQLiteBackend(db_path)
    await storage.connect()

    # Read all fingerprints
    try:
        rows = await storage._conn.execute_fetchall(
            "SELECT ip, port, fingerprint, weight FROM fingerprints"
        )
    except Exception as e:
        print(f"Error reading database: {e}")
        await storage.disconnect()
        return

    if not rows:
        print("No fingerprints found in database.")
        await storage.disconnect()
        return

    # Parse into CameraFingerprint objects
    items = []
    for ip, port, fp_json, weight in rows:
        try:
            fp_data = json.loads(fp_json) if isinstance(fp_json, str) else fp_json
            fp = Fingerprint(**fp_data)
            items.append(CameraFingerprint(ip=ip, port=port, fingerprint=fp, weight=weight or 0.0))
        except Exception as e:
            logger.warning(f"Skip {ip}:{port} — parse error: {e}")

    # Filter
    if args.vendor:
        vendor_lower = args.vendor.lower()
        items = [i for i in items if i.fingerprint.vendor and i.fingerprint.vendor.lower() == vendor_lower]
        print(f"Filtered by vendor: {args.vendor} ({len(items)} targets)")

    if args.limit:
        items = items[: args.limit]
        print(f"Limited to {args.limit} targets")

    total = len(items)
    print(f"Processing {total} targets...\n")

    # Init CVESearcher (without queue — we'll call process() directly)
    cve_searcher = CVESearcher(config.layer3, None, None, storage)

    # Init clients manually
    from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
    from src.layers.layer3_cve_searcher.clients.msf_rpc_client import MSFRPCClient

    cve_searcher._nvd_client = NVDClient(config.layer3.nvd)
    cve_searcher._msf_client = MSFRPCClient(config.layer3.msf)
    try:
        await cve_searcher._msf_client.connect()
        print("msfrpcd: Connected")
    except Exception as e:
        print(f"msfrpcd: Failed ({e}) — MSF check will be skipped")
        cve_searcher._msf_client = None

    print()

    # Process all items with concurrency
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []
    processed = 0
    cve_found = 0
    failed = 0

    async def process_one(item):
        nonlocal processed, cve_found, failed
        async with semaphore:
            try:
                enriched = await cve_searcher.process(item)
                if enriched and enriched.fingerprint.cves:
                    cve_found += 1
                results.append(enriched or item)
            except Exception as e:
                logger.error(f"Error {item.ip}:{item.port}: {e}")
                results.append(item)
                failed += 1
            finally:
                processed += 1
                if processed % 50 == 0 or processed == total:
                    print(f"  [{processed}/{total}] CVE found: {cve_found} | Failed: {failed}")

    tasks = [asyncio.create_task(process_one(item)) for item in items]
    await asyncio.gather(*tasks)

    # Save enriched fingerprints back to DB
    saved = 0
    for item in results:
        if item.fingerprint.cves:
            try:
                await storage._conn.execute(
                    "UPDATE fingerprints SET fingerprint=? WHERE ip=? AND port=?",
                    (item.fingerprint.model_dump_json(), item.ip, item.port)
                )
                saved += 1
            except Exception as e:
                logger.error(f"Save error {item.ip}:{item.port}: {e}")
    await storage._conn.commit()

    # Summary
    print(f"\n{HEADER_BAR}")
    print(f"Done! Processed: {processed} | CVE found: {cve_found} | Failed: {failed} | Saved: {saved}")

    # Show top results
    cve_items = [i for i in results if i.fingerprint.cves]
    if cve_items:
        print(f"\nTargets with CVEs ({len(cve_items)}):\n")
        headers = ["IP", "Port", "Vendor", "Model", "CVEs"]
        widths = [18, 6, 12, 20, 40]
        rows_out = []
        for item in cve_items[:30]:
            fp = item.fingerprint
            cves_str = ", ".join(fp.cves[:3])
            if len(fp.cves) > 3:
                cves_str += f" +{len(fp.cves)-3}"
            rows_out.append([item.ip, str(item.port), fp.vendor or "—", fp.model or "—", cves_str])
        _print_table(headers, rows_out, widths)

    # Cleanup
    if cve_searcher._nvd_client:
        await cve_searcher._nvd_client.close()
    if cve_searcher._msf_client:
        try:
            await cve_searcher._msf_client.disconnect()
        except Exception:
            pass
    await storage.disconnect()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _SimpleQueue:
    """Minimal async queue for test-scan pipeline."""

    def __init__(self):
        self._items = []

    async def put(self, item):
        self._items.append(item)

    async def get(self):
        if self._items:
            return self._items.pop(0)
        await asyncio.sleep(0.1)
        if self._items:
            return self._items.pop(0)
        raise asyncio.TimeoutError

    def size(self):
        return len(self._items)

    async def ack(self, key):
        pass


def _load_config() -> Config:
    try:
        return Config.from_yaml("config/default.yaml")
    except Exception:
        return get_default_config()


def _wrap_text(text, width=72, indent=4):
    """Word-wrap text with indentation."""
    prefix = " " * indent
    words = text.split()
    lines = []
    current = prefix
    for word in words:
        if len(current) + len(word) + 1 > width + indent:
            lines.append(current)
            current = prefix + word
        else:
            current = current + " " + word if current != prefix else prefix + word
    if current != prefix:
        lines.append(current)
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        prog="src.cli",
        description="Layer 3 CVE Search — CLI test tool",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # test-db
    p_db = subparsers.add_parser("test-db", help="Classify fingerprints from existing database")
    p_db.add_argument("--db", help="Path to SQLite database")
    p_db.add_argument("--limit", type=int, help="Limit number of targets")
    p_db.add_argument("--vendor", help="Filter by vendor name")
    p_db.set_defaults(func=cmd_test_db)

    # test-scan
    p_scan = subparsers.add_parser("test-scan", help="End-to-end scan: masscan → fingerprint → CVE")
    p_scan.add_argument("target", help="IP or CIDR range (e.g., 10.0.0.0/24)")
    p_scan.add_argument("--port", default="80,554,8080,8443", help="Ports to scan (default: 80,554,8080,8443)")
    p_scan.add_argument("--rate", type=int, default=1000, help="Masscan rate (default: 1000)")
    p_scan.set_defaults(func=cmd_test_scan)

    # test-nvd
    p_nvd = subparsers.add_parser("test-nvd", help="Query NVD API directly")
    p_nvd.add_argument("query", help="CVE ID (e.g., CVE-2021-36260) or keyword (e.g., hikvision)")
    p_nvd.add_argument("--api-key", help="Override NVD API key")
    p_nvd.set_defaults(func=cmd_test_nvd)

    # run-layer3
    p_run = subparsers.add_parser("run-layer3", help="Run full Layer 3 CVE search on all DB fingerprints")
    p_run.add_argument("--db", help="Path to SQLite database")
    p_run.add_argument("--limit", type=int, help="Limit number of targets")
    p_run.add_argument("--vendor", help="Filter by vendor name")
    p_run.add_argument("--concurrency", type=int, default=10, help="Concurrent targets (default: 10)")
    p_run.set_defaults(func=cmd_run_layer3)

    # test-msf
    p_msf = subparsers.add_parser("test-msf", help="Test msfrpcd connection and module search")
    p_msf.add_argument("--password", help="msfrpcd password")
    p_msf.add_argument("--host", default="127.0.0.1", help="msfrpcd host (default: 127.0.0.1)")
    p_msf.add_argument("--port", default="55553", help="msfrpcd port (default: 55553)")
    p_msf.add_argument("--search", help="Search modules for vendor keyword")
    p_msf.set_defaults(func=cmd_test_msf)

    args = parser.parse_args()
    if hasattr(args, "func"):
        asyncio.run(args.func(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
