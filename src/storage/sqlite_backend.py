"""SQLite backend implementation."""
import aiosqlite
import json
from typing import List, Any
from .base import StorageBackend
from .schemas import CameraFingerprint


class SQLiteBackend(StorageBackend):
    """SQLite storage backend."""

    def __init__(self, path: str = "data/camera_scan.db"):
        self.path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        await self._create_tables()

    async def _create_tables(self) -> None:
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                ip TEXT,
                port INTEGER,
                timestamp TEXT,
                status TEXT,
                fingerprint TEXT,
                weight REAL,
                PRIMARY KEY (ip, port)
            )
        """)

    async def disconnect(self) -> None:
        if self._conn:
            await self._conn.close()

    async def write(self, collection: str, items: List[Any]) -> int:
        if not self._conn:
            await self.connect()

        if collection == "fingerprints":
            written = 0
            for item in items:
                if isinstance(item, CameraFingerprint):
                    await self._conn.execute(
                        """
                        INSERT OR REPLACE INTO fingerprints
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            item.ip,
                            item.port,
                            item.timestamp.isoformat(),
                            item.status,
                            item.fingerprint.model_dump_json(),
                            item.weight
                        )
                    )
                    written += 1
            await self._conn.commit()
            return written
        return 0

    async def read(self, collection: str, query: dict) -> List[Any]:
        if not self._conn:
            await self.connect()

        if collection == "fingerprints":
            cursor = await self._conn.execute("SELECT * FROM fingerprints")
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                fp_dict = json.loads(row[4])
                results.append(CameraFingerprint(
                    ip=row[0],
                    port=row[1],
                    timestamp=datetime.fromisoformat(row[2]),
                    status=row[3],
                    fingerprint=fp_dict,
                    weight=row[5]
                ))
            return results
        return []

    async def count(self, collection: str) -> int:
        if not self._conn:
            await self.connect()

        if collection == "fingerprints":
            cursor = await self._conn.execute("SELECT COUNT(*) FROM fingerprints")
            row = await cursor.fetchone()
            return row[0] if row else 0
        return 0