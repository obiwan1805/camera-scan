"""SQLite backend with concurrency-safe write pipeline."""
import asyncio
import aiosqlite
import csv
import io
import ipaddress
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
                protocol TEXT,
                auth_info TEXT,
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
                target TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL DEFAULT 'cidr',
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)
        await self._migrate_targets_table()
        await self._migrate_fingerprints_protocol()
        await self._migrate_fingerprints_auth_info()

    async def _migrate_targets_table(self) -> None:
        """Migrate old IoT-device targets table to new scan-target schema."""
        cursor = await self._conn.execute("PRAGMA table_info(targets)")
        columns = await cursor.fetchall()
        col_names = [col[1] for col in columns]

        if "name" in col_names and "target" not in col_names:
            self._logger.info("Migrating targets table: old schema -> new scan-input schema")
            await self._conn.execute("DROP TABLE targets")
            await self._conn.execute("""
                CREATE TABLE targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL DEFAULT 'cidr',
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            await self._conn.commit()

    async def _migrate_fingerprints_protocol(self) -> None:
        """Add protocol column to fingerprints table for existing DBs."""
        cursor = await self._conn.execute("PRAGMA table_info(fingerprints)")
        columns = await cursor.fetchall()
        col_names = [col[1] for col in columns]
        if "protocol" not in col_names:
            await self._conn.execute("ALTER TABLE fingerprints ADD COLUMN protocol TEXT")
            await self._conn.commit()

    async def _migrate_fingerprints_auth_info(self) -> None:
        """Add auth_info column to fingerprints table for existing DBs."""
        cursor = await self._conn.execute("PRAGMA table_info(fingerprints)")
        columns = await cursor.fetchall()
        col_names = [col[1] for col in columns]
        if "auth_info" not in col_names:
            await self._conn.execute("ALTER TABLE fingerprints ADD COLUMN auth_info TEXT")
            await self._conn.commit()

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
                try:
                    if collection == "port_scans":
                        await self._write_port_scans(items)
                    elif collection == "fingerprints":
                        await self._write_fingerprints(items)
                    elif collection == "raw_responses":
                        await self._write_raw_responses(items)
                except Exception as e:
                    sample = items[0] if items else None
                    types = type(sample).__name__ if sample else "?"
                    if hasattr(sample, '__dict__'):
                        types += " fields: " + str({k: type(v).__name__ for k, v in sample.__dict__.items()})
                    self._logger.error(f"Write failed for {collection} ({len(items)} items, type={types}): {e}")
            await self._conn.commit()
        except Exception as e:
            self._logger.error(f"Batch commit failed ({len(batch)} items): {e}")

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
                str(item.fingerprint.model_dump_json()),
                item.weight,
                item.protocol,
            )
            for item in items if isinstance(item, CameraFingerprint)
        ]
        if rows:
            await self._conn.executemany(
                "INSERT OR REPLACE INTO fingerprints VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows
            )

    async def _write_raw_responses(self, items: list[RawResponse]) -> None:
        rows = []
        for item in items:
            if not isinstance(item, RawResponse):
                continue
            rows.append((
                str(item.ip),
                int(item.port),
                str(item.module),
                str(item.endpoint),
                int(item.status_code) if item.status_code is not None else None,
                str(item.content_type) if item.content_type is not None else None,
                bytes(item.truncated_data()),
            ))
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
                    weight=row[5],
                    protocol=row[6] if len(row) > 6 else None,
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

    async def enqueue_claimed_item(self, queue_name: str, item_key: str, item_data: str) -> None:
        """Insert a claim already in 'claimed' state — combines enqueue + claim into one commit."""
        if not self._running:
            return
        await self._conn.execute(
            """INSERT OR IGNORE INTO claims (queue_name, item_key, item_data, status, claimed_at)
               VALUES (?, ?, ?, 'claimed', datetime('now'))""",
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

    async def cleanup_claims(self, max_age_hours: int = 24) -> int:
        """Remove completed/failed claims older than max_age_hours. Returns deleted count."""
        if not self._conn:
            await self.connect()
        cursor = await self._conn.execute(
            """DELETE FROM claims
               WHERE status IN ('done', 'failed')
               AND created_at < datetime('now', ?)""",
            (f"-{max_age_hours} hours",),
        )
        await self._conn.commit()
        return cursor.rowcount

    # --- Admin operations for /target clear (bypass writer queue — direct SQL) ---

    _RESULTS_TABLES = ("port_scans", "fingerprints", "raw_responses", "claims")

    async def clear_results(self) -> dict[str, int]:
        """Delete all rows from results tables. Returns {table: deleted_count}."""
        if not self._conn:
            await self.connect()
        counts: dict[str, int] = {}
        for table in self._RESULTS_TABLES:
            cursor = await self._conn.execute(f"DELETE FROM {table}")
            counts[table] = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        await self._conn.commit()
        return counts

    async def dump_table_csv(self, table: str) -> tuple[str, int]:
        """Dump a results table to CSV. Returns (csv_string, row_count)."""
        if not self._conn:
            await self.connect()

        if table == "port_scans":
            cursor = await self._conn.execute(
                "SELECT ip, port, status, timestamp FROM port_scans ORDER BY ip, port"
            )
            rows = await cursor.fetchall()
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ip", "port", "status", "timestamp"])
            writer.writerows(rows)
            return buf.getvalue(), len(rows)

        if table == "fingerprints":
            cursor = await self._conn.execute(
                "SELECT ip, port, protocol, weight, timestamp, fingerprint FROM fingerprints ORDER BY ip, port"
            )
            rows = await cursor.fetchall()
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ip", "port", "protocol", "vendor", "model", "version", "weight", "cves", "favicon_hash", "html_hash", "dom_hash", "title_hash", "timestamp"])
            for ip, port, protocol, weight, timestamp, fp_json in rows:
                try:
                    fp = json.loads(fp_json) if fp_json else {}
                except Exception:
                    fp = {}
                vendor = fp.get("vendor") or ""
                model = fp.get("model") or ""
                version = fp.get("version") or ""
                cves = ";".join(fp.get("cves") or [])
                favicon_hash = fp.get("favicon_hash") if fp.get("favicon_hash") is not None else ""
                html_hash = fp.get("html_hash") if fp.get("html_hash") is not None else ""
                dom_hash = fp.get("dom_hash") if fp.get("dom_hash") is not None else ""
                title_hash = fp.get("title_hash") if fp.get("title_hash") is not None else ""
                writer.writerow([ip, port, protocol or "", vendor, model, version, weight, cves, favicon_hash, html_hash, dom_hash, title_hash, timestamp])
            return buf.getvalue(), len(rows)

        raise ValueError(f"dump_table_csv does not support table '{table}'")

    # --- Cascade delete by target spec (for /target remove) ---

    _CASCADE_TABLES = ("port_scans", "fingerprints", "raw_responses")

    @staticmethod
    def _target_to_int_range(spec: str) -> tuple[int, int]:
        """Return (start_int, end_int) for an IP/CIDR/range spec."""
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        if "-" in spec:
            parts = spec.split("-")
            if len(parts) == 2:
                start = int(ipaddress.ip_address(parts[0].strip()))
                end = int(ipaddress.ip_address(parts[1].strip()))
                return start, end
        addr = int(ipaddress.ip_address(spec))
        return addr, addr

    @staticmethod
    def _ip_in_range(ip_str: str, start: int, end: int) -> bool:
        try:
            val = int(ipaddress.ip_address(ip_str))
            return start <= val <= end
        except ValueError:
            return False

    async def count_target_results(self, target_spec: str) -> dict[str, int]:
        """Count rows in each results table whose IP falls inside target_spec."""
        if not self._conn:
            await self.connect()
        start, end = self._target_to_int_range(target_spec)
        counts: dict[str, int] = {}
        for table in self._CASCADE_TABLES:
            cursor = await self._conn.execute(f"SELECT ip FROM {table}")
            rows = await cursor.fetchall()
            n = 0
            for (ip,) in rows:
                if self._ip_in_range(ip, start, end):
                    n += 1
            counts[table] = n
        # claims: item_key is "ip:port"
        cursor = await self._conn.execute("SELECT item_key FROM claims")
        rows = await cursor.fetchall()
        n = 0
        for (key,) in rows:
            ip = key.rsplit(":", 1)[0] if ":" in key else key
            if self._ip_in_range(ip, start, end):
                n += 1
        counts["claims"] = n
        return counts

    async def clear_target_results(self, target_spec: str) -> dict[str, int]:
        """Delete rows in port_scans/fingerprints/raw_responses/claims whose IP
        falls inside target_spec. Returns {table: deleted_count}."""
        if not self._conn:
            await self.connect()
        start, end = self._target_to_int_range(target_spec)
        counts: dict[str, int] = {}

        for table in self._CASCADE_TABLES:
            cursor = await self._conn.execute(f"SELECT ip FROM {table}")
            rows = await cursor.fetchall()
            matching = [ip for (ip,) in rows if self._ip_in_range(ip, start, end)]
            deleted = 0
            for i in range(0, len(matching), 500):
                batch = matching[i:i + 500]
                placeholders = ",".join("?" for _ in batch)
                cur = await self._conn.execute(
                    f"DELETE FROM {table} WHERE ip IN ({placeholders})", batch
                )
                if cur.rowcount and cur.rowcount > 0:
                    deleted += cur.rowcount
            counts[table] = deleted

        # claims: filter by item_key prefix "ip:"
        cursor = await self._conn.execute("SELECT item_key FROM claims")
        rows = await cursor.fetchall()
        matching_keys = []
        for (key,) in rows:
            ip = key.rsplit(":", 1)[0] if ":" in key else key
            if self._ip_in_range(ip, start, end):
                matching_keys.append(key)
        deleted = 0
        for i in range(0, len(matching_keys), 500):
            batch = matching_keys[i:i + 500]
            placeholders = ",".join("?" for _ in batch)
            cur = await self._conn.execute(
                f"DELETE FROM claims WHERE item_key IN ({placeholders})", batch
            )
            if cur.rowcount and cur.rowcount > 0:
                deleted += cur.rowcount
        counts["claims"] = deleted

        await self._conn.commit()
        return counts
