#!/usr/bin/env python3
"""Layer 2 Test Mode - Test fingerprinting against IP:port pairs from file."""
import asyncio
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.layers.layer2_fingerprinter.modules import MODULE_REGISTRY
from src.storage.schemas import Fingerprint
from src.storage.sqlite_backend import SQLiteBackend
from src.utils.logging import setup_logger


class Layer2Tester:
    def __init__(self, max_concurrent: int = 50):
        self.logger = setup_logger("Layer2Tester")
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def run_test(
        self,
        targets_file: str,
        modules: Optional[List[str]] = None,
        output_file: str = "data/test_results.json"
    ):
        """Run test against IP:port pairs from file."""
        # Load targets
        targets = self._load_targets(targets_file)
        self.logger.info(f"Loaded {len(targets)} targets from {targets_file}")

        if not targets:
            self.logger.warning("No targets loaded")
            return

        # Select modules
        if modules:
            self.modules = [MODULE_REGISTRY[name]() for name in modules]
            self.logger.info(f"Testing modules: {modules}")
        else:
            self.modules = [MODULE_REGISTRY[name]() for name in MODULE_REGISTRY]
            self.logger.info(f"Testing all modules: {[m.__class__.__name__ for m in self.modules]}")

        # Initialize storage
        storage = SQLiteBackend("data/test_results.db")
        await storage.connect()
        await self._create_tables(storage)

        # Run tests
        self.logger.info(f"Starting tests (max_concurrent={self.max_concurrent})")

        self._start_time = asyncio.get_event_loop().time()
        self._processed = 0
        self._successful = 0
        self._failed = 0
        self._results = []

        # Create tasks for all targets
        tasks = []
        for target in targets:
            task = asyncio.create_task(self._test_target(target))
            tasks.append(task)

        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Save results
        self._save_results(output_file)

        # Final stats
        elapsed = asyncio.get_event_loop().time() - self._start_time
        rate = self._processed / elapsed if elapsed > 0 else 0

        self.logger.info("=" * 50)
        self.logger.info("TEST COMPLETE")
        self.logger.info("=" * 50)
        self.logger.info(f"Processed: {self._processed}")
        self.logger.info(f"Successful: {self._successful} ({self._successful/self._processed*100:.1f}%)")
        self.logger.info(f"Failed: {self._failed} ({self._failed/self._processed*100:.1f}%)")
        self.logger.info(f"Rate: {rate:.1f}/s")
        self.logger.info(f"Time: {elapsed:.1f}s")
        self.logger.info(f"Results saved to: {output_file}")

        await storage.disconnect()

    async def _load_targets(self, targets_file: str) -> List[Tuple[str, int]]:
        """Load IP:port pairs from file."""
        targets = []
        try:
            with open(targets_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse "IP:PORT" format
                    if ":" in line:
                        parts = line.split(":")
                        ip = parts[0].strip()
                        port = int(parts[1].strip())
                        targets.append((ip, port))
                    else:
                        self.logger.warning(f"Invalid format (expected IP:PORT): {line}")
        except FileNotFoundError:
            self.logger.error(f"File not found: {targets_file}")
        except Exception as e:
            self.logger.error(f"Error loading targets: {e}")

        return targets

    async def _test_target(self, target: Tuple[str, int]) -> None:
        """Test a single IP:port against all modules."""
        ip, port = target

        async with self.semaphore:
            result = await self._fingerprint(ip, port)

            if result:
                self._successful += 1
                self._results.append({
                    "ip": ip,
                    "port": port,
                    "vendor": result.vendor,
                    "model": result.model,
                    "version": result.version,
                    "services": result.services,
                    "raw_banner": result.raw_banner,
                    "probe_method": result.probe_method,
                    "evidence": result.evidence,
                    "matched_pattern": result.matched_pattern,
                    "endpoint": result.endpoint
                })
                self.logger.info(f"✓ {ip}:{port} - {result.vendor or 'Unknown'} - {result.model or ''} - {result.version or ''} [{result.probe_method or 'N/A'}]")
            else:
                self._failed += 1
                self._debug_info(ip, port)

            self._processed += 1

            if self._processed % 100 == 0:
                self._print_progress()

    async def _fingerprint(self, ip: str, port: int) -> Optional[Fingerprint]:
        """Fingerprint an IP:port against all modules."""
        for module in self.modules:
            if port in module.supported_ports():
                result = await module.probe(ip, port)
                if result:
                    return result
        return None

    def _debug_info(self, ip: str, port: int):
        """Log debug info for failed probe."""
        # Could add more detailed logging here
        pass

    def _print_progress(self):
        """Print progress periodically."""
        elapsed = asyncio.get_event_loop().time() - self._start_time
        rate = self._processed / elapsed if elapsed > 0 else 0

        self.logger.info(
            f"[Progress] {self._processed} processed | "
            f"{self._successful} success | "
            f"{self._failed} failed | "
            f"{rate:.1f}/s"
        )

    async def _create_tables(self, storage: SQLiteBackend):
        """Create test results table."""
        # Tables already created by SQLiteBackend
        pass

    def _save_results(self, output_file: str):
        """Save results to JSON file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total": len(self._results),
            "successful": self._successful,
            "failed": self._failed,
            "results": self._results
        }

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to {output_file}")

        # Also print summary
        self._print_summary()

    def _print_summary(self):
        """Print summary of results."""
        # Count by vendor
        vendors = {}
        for result in self._results:
            vendor = result.get("vendor", "unknown")
            vendors[vendor] = vendors.get(vendor, 0) + 1

        self.logger.info("\nSummary by vendor:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True):
            self.logger.info(f"  {vendor}: {count}")

        # Show successful results
        if self._successful > 0:
            self.logger.info("\nSuccessful identifications:")
            for result in self._results[:20]:  # Show first 20
                evidence_note = f"\n    Evidence: {result.get('evidence', 'N/A')}" if result.get('evidence') else ""
                self.logger.info(f"  {result['ip']}:{result['port']} - {result['vendor']} - {result['model']} - {result['version']}{evidence_note}")
            if len(self._results) > 20:
                self.logger.info(f"  ... and {len(self._results) - 20} more")


async def main():
    parser = argparse.ArgumentParser(description="Layer 2 Test Mode")
    parser.add_argument("targets_file", help="File containing IP:PORT pairs (one per line)")
    parser.add_argument("--modules", nargs="+", help="Modules to test (default: all)")
    parser.add_argument("--output", default="data/test_results.json", help="Output JSON file")
    parser.add_argument("--max-concurrent", type=int, default=50, help="Max concurrent requests")

    args = parser.parse_args()

    tester = Layer2Tester(max_concurrent=args.max_concurrent)
    await tester.run_test(
        targets_file=args.targets_file,
        modules=args.modules,
        output_file=args.output
    )


if __name__ == "__main__":
    asyncio.run(main())