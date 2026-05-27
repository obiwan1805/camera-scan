"""Main entry point for the camera scanner pipeline."""
import asyncio
import sys
import signal
from src.core.config import get_default_config
from src.pipeline.builder import PipelineBuilder, Pipeline
from src.storage.sqlite_backend import SQLiteBackend
from src.layers import PortScanner, CIDRInputSource, Fingerprinter
from src.core.queue_protocol import InMemoryQueue
from src.utils.logging import setup_logger

shutdown_event = asyncio.Event()

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    shutdown_event.set()

async def main():
    config = get_default_config()
    logger = setup_logger("Main")

    # Setup signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_event.set)

    builder = PipelineBuilder(config)
    storage = builder.build_storage()
    queues = builder.build_queues(storage)

    scanner = PortScanner(
        config=config.layers,
        output_queue=queues[0],
        cidr_file="data/cidrs.txt",
        storage=storage
    )
    fingerprinter = Fingerprinter(
        config=config.layer2,
        input_queue=queues[0],
        output_queue=queues[1],
        storage=storage
    )

    input_source = CIDRInputSource("data/cidrs.txt")

    pipeline = Pipeline(
        layers=[scanner, fingerprinter],
        queues=queues,
        storage=storage,
        input_source=input_source
    )

    try:
        await pipeline.start()
        logger.info("Pipeline started")

        # Wait for scanner to complete or shutdown
        scanner_task = scanner._watcher_task
        if scanner_task:
            done, _ = await asyncio.wait(
                [scanner_task, asyncio.create_task(shutdown_event.wait())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Cancel the unused waiter
            for t in done:
                if t is not scanner_task:
                    t.cancel()
            if shutdown_event.is_set():
                logger.info("Shutdown requested, stopping...")

        # Wait for fingerprinter to finish processing or shutdown
        logger.info("Scanner finished, waiting for fingerprinter to complete...")
        while queues[0].size() > 0 and fingerprinter._running:
            await asyncio.sleep(1)
            if shutdown_event.is_set():
                logger.info("Shutdown requested, stopping...")
                break

    except asyncio.CancelledError:
        logger.info("Task cancelled, shutting down...")
    except Exception as e:
        logger.error(f"Error in main loop: {e}")
    finally:
        logger.info("Stopping pipeline...")
        await pipeline.stop()
        logger.info("Pipeline stopped")

        # Print summary
        total_discovered = scanner._discovered
        total_processed = fingerprinter._processed
        total_successful = fingerprinter._successful
        port_scan_count = await storage.count("port_scans")
        fp_count = await storage.count("fingerprints")

        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Total discovered:   {total_discovered}")
        print(f"Total processed:    {total_processed}")
        print(f"Successful:         {total_successful}")
        print(f"Failed:             {fingerprinter._failed}")
        print(f"Skipped (resumed):  {fingerprinter._skipped}")
        print(f"Success rate:       {total_successful/total_processed*100 if total_processed > 0 else 0:.1f}%")
        print(f"Port scans in DB:   {port_scan_count}")
        print(f"Fingerprints in DB: {fp_count}")
        print("="*50)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")