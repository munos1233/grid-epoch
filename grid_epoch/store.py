"""终端档案和审计。库存标识和标志，不存种子、主密钥或协同分片。"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class RegistryStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS terminal (
                tid INTEGER PRIMARY KEY,
                area INTEGER NOT NULL,
                zone INTEGER NOT NULL,
                cohort INTEGER NOT NULL,
                leaf INTEGER NOT NULL,
                local_index INTEGER NOT NULL,
                revoked INTEGER NOT NULL,
                released INTEGER NOT NULL,
                destroyed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_archive (
                id INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def clear_audit(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM audit")
            self._db.commit()

    def upsert_terminal(
        self,
        tid: int,
        area: int,
        zone: int,
        cohort: int,
        leaf: int,
        local_index: int,
        revoked: bool,
        released: bool,
        destroyed: bool = False,
    ) -> None:
        with self._lock:
            self._db.execute(
                """
                INSERT INTO terminal (tid, area, zone, cohort, leaf, local_index, revoked, released, destroyed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tid) DO UPDATE SET
                    revoked=excluded.revoked,
                    released=excluded.released,
                    leaf=excluded.leaf,
                    destroyed=excluded.destroyed
                """,
                (tid, area, zone, cohort, leaf, local_index, int(revoked), int(released), int(destroyed)),
            )
            self._db.commit()

    def audit(self, action: str, detail: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO audit (action, detail) VALUES (?, ?)", (action, detail))
            self._db.commit()

    def archive_before(self, before_id: int) -> int:
        """把更早的审计移入归档表。热表不再留这些行，归档仍可查。"""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, action, detail FROM audit WHERE id < ?",
                (before_id,),
            ).fetchall()
            for row in rows:
                self._db.execute(
                    "INSERT OR REPLACE INTO audit_archive (id, action, detail) VALUES (?, ?, ?)",
                    (row["id"], row["action"], row["detail"]),
                )
            self._db.execute("DELETE FROM audit WHERE id < ?", (before_id,))
            self._db.commit()
        return len(rows)

    def archived_audit(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, action, detail FROM audit_archive ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def destroy_terminal(self, tid: int) -> None:
        with self._lock:
            self._db.execute("UPDATE terminal SET destroyed=1 WHERE tid=?", (tid,))
            self._db.commit()

    def recent_audit(self, limit: int = 12) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, action, detail FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_terminal(self, zone: int, local_index: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM terminal WHERE zone=? AND local_index=? AND released=0",
                (zone, local_index),
            ).fetchone()
        return dict(row) if row else None

    def zone_page(self, page: int, size: int) -> tuple[list[dict], int]:
        with self._lock:
            total = self._db.execute("SELECT COUNT(DISTINCT zone) FROM terminal").fetchone()[0]
            rows = self._db.execute(
                """
                SELECT zone,
                       SUM(CASE WHEN released=0 AND revoked=0 AND destroyed=0 THEN 1 ELSE 0 END) AS enrolled,
                       SUM(CASE WHEN revoked=1 AND released=0 AND destroyed=0 THEN 1 ELSE 0 END) AS revoked,
                       SUM(CASE WHEN destroyed=1 AND released=0 THEN 1 ELSE 0 END) AS destroyed
                FROM terminal
                GROUP BY zone
                ORDER BY zone
                LIMIT ? OFFSET ?
                """,
                (size, page * size),
            ).fetchall()
        return [dict(row) for row in rows], total
