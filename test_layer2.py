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

from src.layers.layer2_fingerprinter.signatures.loader import SignatureLoader
from src.layers.layer2_fingerprinter.engine import SignatureEngine
from src.layers.layer2_fingerprinter.resolver import AggregationResolver
from src.layers.layer2_fingerprinter.probers import (
    HTTPProber, HTTPSProber, RTSPProber, ONVIFProber, FaviconProber, CollectedData,
)
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
        output_file: str = "data/test_results.json"
    ):
        """Run test against IP:port pairs from file."""
        targets = self._load_targets(targets_file)
        self.logger.info(f"Loaded {len(targets)} targets from {targets_file}")

        if not targets:
            self.logger.warning("No targets loaded")
            return

        # Load signatures
        loader = SignatureLoader("config/signatures")
        engine = SignatureEngine(loader.signatures)
        resolver = AggregationResolver()

        self.logger.info(f"Loaded {len(loader.signatures)} vendor signatures")

        # Build probers
        endpoints = loader.get_unique_endpoint_paths()
        rtsp_paths = loader.get_all_rtsp_paths()

        self._probers = [
            HTTPProber(endpoint_paths=endpoints),
            HTTPSProber(endpoint_paths=endpoints),
            RTSPProber(extra_paths=rtsp_paths),
            ONVIFProber(),
            FaviconProber(),
        ]

        # Initialize storage
        storage = SQLiteBackend("data/test_results.db")
        await storage.connect()

        # Run tests
        self.logger.info(f"Starting tests (max_concurrent={self.max_concurrent})")

        self._start_time = asyncio.get_event_loop().time()
        self._processed = 0
        self._successful = 0
        self._failed = 0
        self._results = []

        tasks = []
        for target in targets:
            task = asyncio.create_task(self._test_target(target, engine, resolver))
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

        # Save results
        self._save_results(output_file)

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

        await storage.disconnect()

    def _load_targets(self, targets_file: str) -> List[Tuple[str, int]]:
        targets = []
        try:
            with open(targets_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        parts = line.split(":")
                        ip = parts[0].strip()
                        port = int(parts[1].strip())
                        targets.append((ip, port))
                    else:
                        self.logger.warning(f"Invalid format (expected IP:PORT): {line}")
        except FileNotFoundError:
            self.logger.error(f"File not found: {targets_file}")
        return targets

    async def _test_target(
        self, target: Tuple[str, int],
        engine: SignatureEngine,
        resolver: AggregationResolver
    ) -> None:
        ip, port = target

        async with self.semaphore:
            # Phase 1: Collect
            collected = CollectedData(ip=ip, port=port)
            for prober in self._probers:
                if port in prober.supported_ports():
                    collected = await prober.probe(ip, port, collected)

            # Phase 2: Match
            matches = engine.match(collected)

            # Phase 3: Resolve
            fp = resolver.resolve(matches)

            if fp:
                self._successful += 1
                self._results.append({
                    "ip": ip,
                    "port": port,
                    "vendor": fp.vendor,
                    "model": fp.model,
                    "version": fp.version,
                    "cves": fp.cves,
                    "services": fp.services,
                    "evidence_items": [
                        {
                            "field": e.field,
                            "value": e.value,
                            "source": e.source,
                            "pattern": e.pattern,
                            "cves": e.cves,
                        }
                        for e in fp.evidence_items
                    ],
                })
                cves_str = f" cves={fp.cves}" if fp.cves else ""
                self.logger.info(
                    f"[OK] {ip}:{port} - {fp.vendor or 'Unknown'} - "
                    f"{fp.model or ''} {fp.version or ''}{cves_str} "
                    f"({len(fp.evidence_items)} signals)"
                )
            else:
                self._failed += 1

            self._processed += 1
            if self._processed % 100 == 0:
                self._print_progress()

    def _print_progress(self):
        elapsed = asyncio.get_event_loop().time() - self._start_time
        rate = self._processed / elapsed if elapsed > 0 else 0
        self.logger.info(
            f"[Progress] {self._processed} processed | "
            f"{self._successful} success | "
            f"{self._failed} failed | "
            f"{rate:.1f}/s"
        )

    def _save_results(self, output_file: str):
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

        self._print_summary()

    def _print_summary(self):
        vendors = {}
        for result in self._results:
            vendor = result.get("vendor", "unknown")
            vendors[vendor] = vendors.get(vendor, 0) + 1

        self.logger.info("\nSummary by vendor:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True):
            self.logger.info(f"  {vendor}: {count}")

        if self._successful > 0:
            self.logger.info("\nSuccessful identifications:")
            for result in self._results[:20]:
                cves_str = f" cves={result.get('cves', [])}" if result.get('cves') else ""
                signals = len(result.get('evidence_items', []))
                self.logger.info(
                    f"  {result['ip']}:{result['port']} - "
                    f"{result['vendor']} - {result['model']} - "
                    f"{result['version']}{cves_str} ({signals} signals)"
                )
            if len(self._results) > 20:
                self.logger.info(f"  ... and {len(self._results) - 20} more")


async def main():
    parser = argparse.ArgumentParser(description="Layer 2 Test Mode")
    parser.add_argument("targets_file", help="File containing IP:PORT pairs (one per line)")
    parser.add_argument("--output", default="data/test_results.json", help="Output JSON file")
    parser.add_argument("--max-concurrent", type=int, default=50, help="Max concurrent requests")

    args = parser.parse_args()

    tester = Layer2Tester(max_concurrent=args.max_concurrent)
    await tester.run_test(
        targets_file=args.targets_file,
        output_file=args.output
    )


if __name__ == "__main__":
    asyncio.run(main())
