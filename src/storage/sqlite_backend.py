"""SQLite backend with concurrency-safe write pipeline."""
import asyncio
import aiosqlite
import json
from typing import Any, List, Optional
from .base import StorageBackend
from .schemas import CameraFingerprint, PortScanResult, RawResponse
from src.utils.logging import setup_logger


class SQLiteBackend(StorageBackend):
    """SQLite storage backend with internal write queue for safe concurrent writes."""

    def __init__(self, path: str = "data/camera_scan.db", batch_size: int = 100):
        self.path = path
        self._conn: aiosqlite.Connection | None = None
        self._write_queue: asyncio.Queue | None = None
        self._writer_task: asyncio.Task | None = None
        self._batch_size = batch_size
        self._logger = setup_logger("SQLiteBackend")
        self._running = False

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._create_tables()

        self._write_queue = asyncio.Queue()
        self._running = True
        self._writer_task = asyncio.create_task(self._writer_loop())
        self._logger.info(f"SQLite connected ({self.path}, WAL mode, batch_size={self._batch_size})")

    async def _create_tables(self) -> None:
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS port_scans (
                ip TEXT,
                port INTEGER,
                timestamp TEXT,
                status TEXT DEFAULT 'open',
                PRIMARY KEY (ip, port)
            );
            CREATE TABLE IF NOT EXISTS fingerprints (
                ip TEXT,
                port INTEGER,
                timestamp TEXT,
                status TEXT,
                fingerprint TEXT,
                weight REAL,
                PRIMARY KEY (ip, port)
            );
            CREATE TABLE IF NOT EXISTS claims (
                queue_name TEXT,
                item_key TEXT,
                item_data TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT (datetime('now')),
                claimed_at TEXT,
                PRIMARY KEY (queue_name, item_key)
            );
            CREATE TABLE IF NOT EXISTS raw_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                module TEXT,
                endpoint TEXT,
                status_code INTEGER,
                content_type TEXT,
                raw_data BLOB,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_raw_responses_ip_port ON raw_responses(ip, port);
            CREATE TABLE IF NOT EXISTS pocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                cve_id TEXT,
                vendor TEXT,
                target_names TEXT DEFAULT '[]',
                protocol TEXT,
                script_type TEXT,
                script_content TEXT,
                description TEXT,
                severity TEXT,
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS dicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dict_type TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                aliases TEXT DEFAULT '[]',
                vendor TEXT,
                category TEXT,
                metadata TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
        """)

    async def disconnect(self) -> None:
        self._running = False

        # Signal writer to flush and exit
        if self._write_queue is not None:
            await self._write_queue.put(None)

        if self._writer_task:
            await asyncio.wait_for(self._writer_task, timeout=10)

        if self._conn:
            await self._conn.close()

    async def submit(self, collection: str, items: List[Any]) -> None:
        """Non-blocking enqueue for concurrent writers. Returns immediately."""
        if not self._running:
            return
        for item in items:
            await self._write_queue.put((collection, item))

    async def _writer_loop(self) -> None:
        """Single writer coroutine that drains the queue in batches."""
        while self._running:
            try:
                batch: list[tuple[str, Any]] = []

                # Wait for first item (or shutdown sentinel)
                first = await asyncio.wait_for(self._write_queue.get(), timeout=1.0)
                if first is None:
                    break
                batch.append(first)

                # Drain any queued items up to batch_size
                while len(batch) < self._batch_size:
                    try:
                        item = self._write_queue.get_nowait()
                        if item is None:
                            break
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    await self._flush_batch(batch)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self._logger.error(f"Writer loop error: {e}")

        # Final flush on shutdown — drain anything left in the queue
        remaining = []
        while True:
            try:
                item = self._write_queue.get_nowait()
                if item is not None:
                    remaining.append(item)
            except asyncio.QueueEmpty:
                break
        if remaining:
            await self._flush_batch(remaining)

    async def _flush_batch(self, batch: list[tuple[str, Any]]) -> None:
        """Write a batch of items in a single transaction."""
        # Group by collection for efficient inserts
        by_collection: dict[str, list[Any]] = {}
        for collection, item in batch:
            by_collection.setdefault(collection, []).append(item)

        try:
            for collection, items in by_collection.items():
                if collection == "port_scans":
                    await self._write_port_scans(items)
                elif collection == "fingerprints":
                    await self._write_fingerprints(items)
                elif collection == "raw_responses":
                    await self._write_raw_responses(items)
            await self._conn.commit()
        except Exception as e:
            self._logger.error(f"Batch write failed ({len(batch)} items): {e}")

    async def _write_port_scans(self, items: list[PortScanResult]) -> None:
        rows = [
            (item.ip, item.port, item.timestamp.isoformat(), item.status)
            for item in items if isinstance(item, PortScanResult)
        ]
        if rows:
            await self._conn.executemany(
                "INSERT OR REPLACE INTO port_scans VALUES (?, ?, ?, ?)",
                rows
            )

    async def _write_fingerprints(self, items: list[CameraFingerprint]) -> None:
        rows = [
            (
                item.ip,
                item.port,
                item.timestamp.isoformat(),
                item.status,
                item.fingerprint.model_dump_json(),
                item.weight
            )
            for item in items if isinstance(item, CameraFingerprint)
        ]
        if rows:
            await self._conn.executemany(
                "INSERT OR REPLACE INTO fingerprints VALUES (?, ?, ?, ?, ?, ?)",
                rows
            )

    async def _write_raw_responses(self, items: list[RawResponse]) -> None:
        rows = [
            (
                item.ip,
                item.port,
                item.module,
                item.endpoint,
                item.status_code,
                item.content_type,
                item.truncated_data()
            )
            for item in items if isinstance(item, RawResponse)
        ]
        if rows:
            await self._conn.executemany(
                "INSERT INTO raw_responses (ip, port, module, endpoint, status_code, content_type, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows
            )

    async def write(self, collection: str, items: List[Any]) -> int:
        """Blocking write — routes through the internal queue and waits for completion."""
        if not self._conn:
            await self.connect()
        count = len(items)
        await self.submit(collection, items)
        return count

    async def read(self, collection: str, query: dict) -> List[Any]:
        if not self._conn:
            await self.connect()

        if collection == "fingerprints":
            cursor = await self._conn.execute("SELECT * FROM fingerprints")
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                fp_dict = json.loads(row[4])
                from datetime import datetime
                results.append(CameraFingerprint(
                    ip=row[0],
                    port=row[1],
                    timestamp=datetime.fromisoformat(row[2]),
                    status=row[3],
                    fingerprint=fp_dict,
                    weight=row[5]
                ))
            return results
        elif collection == "port_scans":
            cursor = await self._conn.execute("SELECT * FROM port_scans")
            rows = await cursor.fetchall()
            from datetime import datetime
            return [
                PortScanResult(ip=row[0], port=row[1], timestamp=datetime.fromisoformat(row[2]), status=row[3])
                for row in rows
            ]
        return []

    async def count(self, collection: str) -> int:
        if not self._conn:
            await self.connect()

        if collection in ("fingerprints", "port_scans"):
            cursor = await self._conn.execute(f"SELECT COUNT(*) FROM {collection}")
            row = await cursor.fetchone()
            return row[0] if row else 0
        return 0

    # --- Queue operations (bypass write queue — small, synchronous ops) ---

    async def enqueue_item(self, queue_name: str, item_key: str, item_data: str) -> None:
        if not self._running:
            return
        await self._conn.execute(
            "INSERT OR IGNORE INTO claims (queue_name, item_key, item_data) VALUES (?, ?, ?)",
            (queue_name, item_key, item_data)
        )
        await self._conn.commit()

    async def claim_item(self, queue_name: str, item_key: str) -> None:
        if not self._running:
            return
        await self._conn.execute(
            "UPDATE claims SET status='claimed', claimed_at=datetime('now') WHERE queue_name=? AND item_key=?",
            (queue_name, item_key)
        )
        await self._conn.commit()

    async def ack_item(self, queue_name: str, item_key: str) -> None:
        if not self._running:
            return
        await self._conn.execute(
            "UPDATE claims SET status='done' WHERE queue_name=? AND item_key=?",
            (queue_name, item_key)
        )
        await self._conn.commit()

    async def fail_item(self, queue_name: str, item_key: str) -> None:
        if not self._running:
            return
        await self._conn.execute(
            "UPDATE claims SET status='failed' WHERE queue_name=? AND item_key=?",
            (queue_name, item_key)
        )
        await self._conn.commit()

    async def recover_queue(
        self, queue_name: str, source_collection: str, sink_collection: Optional[str]
    ) -> List[tuple]:
        # Step 1: Reset crashed claims back to pending
        await self._conn.execute(
            "UPDATE claims SET status='pending', claimed_at=NULL WHERE queue_name=? AND status='claimed'",
            (queue_name,)
        )
        await self._conn.commit()

        # Step 2: Find items in source that are NOT in sink and NOT done/failed
        if source_collection == "port_scans":
            if sink_collection == "fingerprints":
                cursor = await self._conn.execute("""
                    SELECT ps.ip, ps.port FROM port_scans ps
                    WHERE NOT EXISTS (
                        SELECT 1 FROM fingerprints f WHERE f.ip = ps.ip AND f.port = ps.port
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM claims c
                        WHERE c.queue_name = ? AND c.item_key = ps.ip || ':' || ps.port
                        AND c.status IN ('done', 'failed')
                    )
                """, (queue_name,))
            else:
                cursor = await self._conn.execute("""
                    SELECT ps.ip, ps.port FROM port_scans ps
                    WHERE NOT EXISTS (
                        SELECT 1 FROM claims c
                        WHERE c.queue_name = ? AND c.item_key = ps.ip || ':' || ps.port
                        AND c.status IN ('done', 'failed')
                    )
                """, (queue_name,))
        elif source_collection == "fingerprints":
            if sink_collection:
                cursor = await self._conn.execute(f"""
                    SELECT f.ip, f.port, f.timestamp, f.status, f.fingerprint, f.weight
                    FROM fingerprints f
                    WHERE NOT EXISTS (
                        SELECT 1 FROM {sink_collection} s WHERE s.ip = f.ip AND s.port = f.port
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM claims c
                        WHERE c.queue_name = ? AND c.item_key = f.ip || ':' || f.port
                        AND c.status IN ('done', 'failed')
                    )
                """, (queue_name,))
            else:
                cursor = await self._conn.execute("""
                    SELECT f.ip, f.port, f.timestamp, f.status, f.fingerprint, f.weight
                    FROM fingerprints f
                    WHERE NOT EXISTS (
                        SELECT 1 FROM claims c
                        WHERE c.queue_name = ? AND c.item_key = f.ip || ':' || f.port
                        AND c.status IN ('done', 'failed')
                    )
                """, (queue_name,))
        else:
            return []

        rows = await cursor.fetchall()

        # Step 3: Ensure claim entries exist for all pending items
        for row in rows:
            item_key = f"{row[0]}:{row[1]}"
            if source_collection == "port_scans":
                item_data = json.dumps({"ip": row[0], "port": row[1]})
            else:
                item_data = json.dumps({
                    "ip": row[0], "port": row[1], "timestamp": row[2],
                    "status": row[3], "fingerprint": row[4], "weight": row[5]
                })
            await self._conn.execute(
                "INSERT OR IGNORE INTO claims (queue_name, item_key, item_data, status) VALUES (?, ?, ?, 'pending')",
                (queue_name, item_key, item_data)
            )
        await self._conn.commit()

        # Step 4: Return pending items
        if source_collection == "port_scans":
            return [(row[0], row[1]) for row in rows]
        else:
            from datetime import datetime
            return [
                CameraFingerprint(
                    ip=row[0], port=row[1],
                    timestamp=datetime.fromisoformat(row[2]),
                    status=row[3],
                    fingerprint=json.loads(row[4]),
                    weight=row[5]
                )
                for row in rows
            ]

    async def has_fingerprint(self, ip: str, port: int) -> bool:
        if not self._conn:
            await self.connect()
        cursor = await self._conn.execute(
            "SELECT 1 FROM fingerprints WHERE ip=? AND port=?", (ip, port)
        )
        return await cursor.fetchone() is not None

    # --- Generic CRUD for bot-managed tables (pocs, dicts, targets) ---

    _ALLOWED_CRUD_TABLES = {"pocs", "dicts", "targets"}

    async def generic_insert(self, table: str, data: dict) -> int:
        if table not in self._ALLOWED_CRUD_TABLES:
            raise ValueError(f"Table '{table}' not allowed for generic CRUD")
        if not self._conn:
            await self.connect()
        columns = list(data.keys())
        placeholders = ", ".join("?" for _ in columns)
        col_str = ", ".join(columns)
        values = [data[c] for c in columns]
        cursor = await self._conn.execute(
            f"INSERT INTO {table} ({col_str}) VALUES ({placeholders})", values
        )
        await self._conn.commit()
        return cursor.lastrowid

    async def generic_delete(self, table: str, row_id: int) -> bool:
        if table not in self._ALLOWED_CRUD_TABLES:
            raise ValueError(f"Table '{table}' not allowed for generic CRUD")
        if not self._conn:
            await self.connect()
        cursor = await self._conn.execute(
            f"DELETE FROM {table} WHERE id = ?", (row_id,)
        )
        await self._conn.commit()
        return cursor.rowcount > 0

    async def generic_list(self, table: str, filters: Optional[dict] = None) -> List[dict]:
        if table not in self._ALLOWED_CRUD_TABLES:
            raise ValueError(f"Table '{table}' not allowed for generic CRUD")
        if not self._conn:
            await self.connect()
        if filters:
            clauses = " AND ".join(f"{k} = ?" for k in filters)
            values = list(filters.values())
            cursor = await self._conn.execute(
                f"SELECT * FROM {table} WHERE {clauses}", values
            )
        else:
            cursor = await self._conn.execute(f"SELECT * FROM {table}")
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    async def generic_get(self, table: str, row_id: int) -> Optional[dict]:
        if table not in self._ALLOWED_CRUD_TABLES:
            raise ValueError(f"Table '{table}' not allowed for generic CRUD")
        if not self._conn:
            await self.connect()
        cursor = await self._conn.execute(
            f"SELECT * FROM {table} WHERE id = ?", (row_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))
