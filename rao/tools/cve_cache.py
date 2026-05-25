"""Local SQLite cache for CVE data — survives NVD API outages.

CVE data is cached for 7 days. Expired entries are automatically
refreshed on next access. The cache database lives in the project
data/ directory and is excluded from version control.
"""

from __future__ import annotations

import atexit
import json
import logging
import sqlite3
import time
from pathlib import Path

from rao.config import ROOT_DIR

logger = logging.getLogger(__name__)

CACHE_DB = ROOT_DIR / "data" / "cve_cache.db"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


class CVECache:
    """Persistent SQLite cache for CVE lookup results."""

    def __init__(self, db_path: Path = CACHE_DB) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        # BUG #21 fix: WAL mode allows concurrent reads and writes without
        # database corruption when multiple threads access the cache.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS cves (
                keyword   TEXT PRIMARY KEY,
                data      TEXT NOT NULL,
                cached_at REAL NOT NULL
            )"""
        )
        self._conn.commit()
        # BUG #22 fix: use atexit for deterministic cleanup instead of __del__.
        # __del__ is called by the GC in non-deterministic order and may run
        # after sqlite3 is already unloaded.
        atexit.register(self._close)

    def get(self, keyword: str) -> list[dict] | None:
        """Return cached results for keyword if still fresh, else None."""
        row = self._conn.execute(
            "SELECT data, cached_at FROM cves WHERE keyword = ?",
            (keyword,),
        ).fetchone()

        if row is None:
            return None

        age = time.time() - row[1]
        if age > CACHE_TTL_SECONDS:
            logger.debug("CVE cache expired for '%s' (age=%.0fs)", keyword, age)
            return None

        logger.debug("CVE cache hit for '%s' (age=%.0fs)", keyword, age)
        return json.loads(row[0])

    def set(self, keyword: str, data: list[dict]) -> None:
        """Store results for keyword with current timestamp."""
        self._conn.execute(
            "INSERT OR REPLACE INTO cves (keyword, data, cached_at) VALUES (?, ?, ?)",
            (keyword, json.dumps(data), time.time()),
        )
        self._conn.commit()

    def clear_expired(self) -> int:
        """Remove all expired entries. Returns number of rows deleted."""
        cutoff = time.time() - CACHE_TTL_SECONDS
        cursor = self._conn.execute(
            "DELETE FROM cves WHERE cached_at < ?", (cutoff,)
        )
        self._conn.commit()
        return cursor.rowcount

    def _close(self) -> None:
        """Close the SQLite connection. Called by atexit."""
        try:
            self._conn.close()
        except Exception:
            pass
