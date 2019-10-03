# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from time import time
from pathlib import Path
from async_generator import asynccontextmanager
from sqlite3 import connect as sqlite_connect

from parsec.core.types import ChunkID
from parsec.core.fs.exceptions import FSLocalMissError
from parsec.core.types import LocalDevice, DEFAULT_BLOCK_SIZE


class BaseChunkStorage:
    def __init__(self, device: LocalDevice, path: Path):
        self.local_symkey = device.local_symkey
        self.path = Path(path)
        self._conn = None

    @classmethod
    @asynccontextmanager
    async def run(cls, *args, **kwargs):
        self = cls(*args, **kwargs)
        try:
            await self._connect()
            yield self
        finally:
            await self._close()

    # Life cycle

    async def _create_connection(self):
        # Create directories
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Create sqlite connection
        conn = sqlite_connect(str(self.path))

        # Set fast auto-commit mode
        conn.isolation_level = None
        conn.execute("pragma journal_mode=wal")
        conn.execute("PRAGMA synchronous = OFF")

        # Return connection
        return conn

    async def _connect(self):
        if self._conn is not None:
            raise RuntimeError("Already connected")

        # Connect and initialize database
        self._conn = await self._create_connection()

        # Initialize
        await self._create_db()

    async def _close(self):
        # Idempotency
        if self._conn is None:
            return

        # Auto-commit is used but do it once more just in case
        self._conn.commit()
        self._conn.close()
        self._conn = None

    # Cursor management

    @asynccontextmanager
    async def _open_cursor(self):
        cursor = self._conn.cursor()
        # Automatic rollback on exception
        with self._conn:
            try:
                yield cursor
            finally:
                cursor.close()

    # Database initialization

    async def _create_db(self):
        async with self._open_cursor() as cursor:
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS chunks
                    (chunk_id BLOB PRIMARY KEY NOT NULL, -- UUID
                     size INTEGER NOT NULL,
                     offline INTEGER NOT NULL,  -- Boolean
                     accessed_on INTEGER, -- Timestamp
                     data BLOB NOT NULL
                );"""
            )

    # Size and chunks

    async def get_nb_blocks(self):
        async with self._open_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM chunks")
            result, = cursor.fetchone()
            return result

    async def get_total_size(self):
        async with self._open_cursor() as cursor:
            cursor.execute("SELECT COALESCE(SUM(size), 0) FROM chunks")
            result, = cursor.fetchone()
            return result

    def get_disk_usage(self):
        disk_usage = 0
        for suffix in (".sqlite", ".sqlite-wal", ".sqlite-shm"):
            try:
                disk_usage += self.path.with_suffix(suffix).stat().st_size
            except OSError:
                pass
        return disk_usage

    # Generic chunk operations

    async def is_chunk(self, chunk_id: ChunkID):
        async with self._open_cursor() as cursor:
            cursor.execute("SELECT chunk_id FROM chunks WHERE chunk_id = ?", (chunk_id.bytes,))
            manifest_row = cursor.fetchone()
        return bool(manifest_row)

    async def get_chunk(self, chunk_id: ChunkID):
        async with self._open_cursor() as cursor:
            cursor.execute("BEGIN")
            cursor.execute(
                """
                UPDATE chunks SET accessed_on = ? WHERE chunk_id = ?;
                """,
                (time(), chunk_id.bytes),
            )
            cursor.execute("SELECT changes()")
            changes, = cursor.fetchone()
            if not changes:
                raise FSLocalMissError(chunk_id)

            cursor.execute("""SELECT data FROM chunks WHERE chunk_id = ?""", (chunk_id.bytes,))
            ciphered, = cursor.fetchone()
            cursor.execute("END")

        return self.local_symkey.decrypt(ciphered)

    async def set_chunk(self, chunk_id: ChunkID, raw: bytes):
        assert isinstance(raw, (bytes, bytearray))
        ciphered = self.local_symkey.encrypt(raw)

        # Update database
        async with self._open_cursor() as cursor:
            cursor.execute(
                """INSERT OR REPLACE INTO
                chunks (chunk_id, size, offline, accessed_on, data)
                VALUES (?, ?, ?, ?, ?)""",
                (chunk_id.bytes, len(ciphered), False, time(), ciphered),
            )

    async def clear_chunk(self, chunk_id: ChunkID):
        async with self._open_cursor() as cursor:
            cursor.execute("BEGIN")
            cursor.execute("DELETE FROM chunks WHERE chunk_id = ?", (chunk_id.bytes,))
            cursor.execute("SELECT changes()")
            changes, = cursor.fetchone()
            cursor.execute("END")

        if not changes:
            raise FSLocalMissError(chunk_id)


class ChunkStorage(BaseChunkStorage):
    def __init__(self, device: LocalDevice, path: Path, vacuum_threshold: int):
        super().__init__(device, path)
        self.vacuum_threshold = vacuum_threshold

    # Vacuum

    async def run_vacuum(self):
        if self.get_disk_usage() > self.vacuum_threshold:
            self._conn.execute("VACUUM")

            # The connection needs to be recreated
            await self._close()
            self._conn = await self._create_connection()


class BlockStorage(BaseChunkStorage):
    def __init__(self, device: LocalDevice, path: Path, cache_size: int):
        super().__init__(device, path)
        self.cache_size = cache_size

    # Garbage collection

    @property
    def block_limit(self):
        return self.cache_size // DEFAULT_BLOCK_SIZE

    async def clear_all_blocks(self):
        async with self._open_cursor() as cursor:
            cursor.execute("DELETE FROM chunks")

    async def clear_old_blocks(self, limit):
        async with self._open_cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM chunks WHERE chunk_id IN (
                    SELECT chunk_id FROM chunks ORDER BY accessed_on ASC LIMIT ?
                )
                """,
                (limit,),
            )

    # Upgraded set method

    async def set_chunk(self, chunk_id: ChunkID, raw: bytes):
        # Actual set operation
        await super().set_chunk(chunk_id, raw)

        # Clean up if necessary
        nb_blocks = await self.get_nb_blocks()
        limit = nb_blocks - self.block_limit
        if limit > 0:
            await self.clear_old_blocks(limit=limit)
