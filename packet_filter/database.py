"""SQLite-backed whitelist storage.

Used only by the management API and by cache reloads. The packet-processing
hot path never touches this module.
"""
import ipaddress
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import config

logger = logging.getLogger("packet_filter.database")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_ip TEXT NOT NULL UNIQUE,
    label TEXT,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    whitelist_id INTEGER,
    destination_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
"""


class WhitelistNotFoundError(Exception):
    pass


class DuplicateIPError(Exception):
    pass


class Database:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DB_PATH
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(f"PRAGMA busy_timeout={config.DB_BUSY_TIMEOUT_MS}")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        logger.info("database initialised", extra={"event": "db_init", "db_path": self.db_path})

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _audit(self, whitelist_id, destination_ip: str, action: str, detail: str = None) -> None:
        self._conn.execute(
            "INSERT INTO whitelist_audit (whitelist_id, destination_ip, action, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (whitelist_id, destination_ip, action, detail, self._now()),
        )

    def _get_entry_locked(self, entry_id: int) -> dict:
        row = self._conn.execute("SELECT * FROM whitelist WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            raise WhitelistNotFoundError(entry_id)
        return self._row_to_entry(row)

    def _get_entry_by_ip_locked(self, destination_ip: str) -> dict:
        row = self._conn.execute("SELECT * FROM whitelist WHERE destination_ip = ?", (destination_ip,)).fetchone()
        if row is None:
            raise WhitelistNotFoundError(destination_ip)
        return self._row_to_entry(row)

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> dict:
        entry = dict(row)
        entry["active"] = bool(entry["active"])
        return entry

    def add_entry(self, destination_ip: str, label: str = None) -> dict:
        ipaddress.IPv4Address(destination_ip)
        now = self._now()
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "INSERT INTO whitelist (destination_ip, label, active, created_at, updated_at) "
                    "VALUES (?, ?, 1, ?, ?)",
                    (destination_ip, label, now, now),
                )
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise DuplicateIPError(destination_ip) from exc
            self._audit(cursor.lastrowid, destination_ip, "CREATE", label)
            self._conn.commit()
            entry = self._get_entry_locked(cursor.lastrowid)
        logger.info("whitelist entry created", extra={"event": "whitelist_create", "destination_ip": destination_ip})
        return entry

    def get_entry(self, entry_id: int) -> dict:
        with self._lock:
            return self._get_entry_locked(entry_id)

    def list_entries(self) -> list:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
            return [self._row_to_entry(row) for row in rows]

    def get_active_ips(self) -> list:
        with self._lock:
            rows = self._conn.execute("SELECT destination_ip FROM whitelist WHERE active = 1").fetchall()
            return [row["destination_ip"] for row in rows]

    def is_active_ip(self, destination_ip: str) -> bool:
        """Point lookup used as a fallback when the in-memory cache misses."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM whitelist WHERE destination_ip = ? AND active = 1", (destination_ip,)
            ).fetchone()
            return row is not None

    def set_active(self, entry_id: int, active: bool) -> dict:
        now = self._now()
        with self._lock:
            entry = self._get_entry_locked(entry_id)
            self._conn.execute(
                "UPDATE whitelist SET active = ?, updated_at = ? WHERE id = ?",
                (1 if active else 0, now, entry_id),
            )
            self._audit(entry_id, entry["destination_ip"], "ENABLE" if active else "DISABLE")
            self._conn.commit()
            updated = self._get_entry_locked(entry_id)
        logger.info(
            "whitelist entry updated",
            extra={"event": "whitelist_update", "destination_ip": entry["destination_ip"], "active": active},
        )
        return updated

    def set_active_by_ip(self, destination_ip: str, active: bool) -> dict:
        now = self._now()
        with self._lock:
            entry = self._get_entry_by_ip_locked(destination_ip)
            self._conn.execute(
                "UPDATE whitelist SET active = ?, updated_at = ? WHERE id = ?",
                (1 if active else 0, now, entry["id"]),
            )
            self._audit(entry["id"], destination_ip, "ENABLE" if active else "DISABLE")
            self._conn.commit()
            updated = self._get_entry_by_ip_locked(destination_ip)
        logger.info(
            "whitelist entry updated",
            extra={"event": "whitelist_update", "destination_ip": destination_ip, "active": active},
        )
        return updated

    def delete_entry(self, entry_id: int) -> None:
        with self._lock:
            entry = self._get_entry_locked(entry_id)
            self._conn.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
            self._audit(entry_id, entry["destination_ip"], "DELETE")
            self._conn.commit()
        logger.info(
            "whitelist entry deleted",
            extra={"event": "whitelist_delete", "destination_ip": entry["destination_ip"]},
        )
