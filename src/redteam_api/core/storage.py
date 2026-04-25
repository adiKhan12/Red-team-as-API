from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from redteam_api.core.models import AttackAttempt, Finding, FindingCategory, ScanStatus, Severity

DB_PATH = Path(__file__).resolve().parents[3] / "data" / "redteam.db"

SQL_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'queued',
    request_json TEXT NOT NULL,
    attempts_run INTEGER NOT NULL DEFAULT 0,
    attempts_total INTEGER NOT NULL DEFAULT 0,
    cost_total REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    attacker_prompt TEXT NOT NULL,
    target_response TEXT NOT NULL,
    judge_rationale TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    category TEXT NOT NULL,
    attacker_prompt TEXT NOT NULL,
    target_response TEXT,
    judge_result_json TEXT,
    cost REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_attempts_scan ON attempts(scan_id);
"""


class Storage:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or str(DB_PATH)

    async def init(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(SQL_SCHEMA)
            await db.commit()

    async def insert_scan(
        self,
        scan_id: str,
        request_json: str,
        attempts_total: int,
        created_at: str,
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO scans (scan_id, status, request_json, attempts_total, created_at) "
                "VALUES (?, 'queued', ?, ?, ?)",
                (scan_id, request_json, attempts_total, created_at),
            )
            await db.commit()

    async def update_scan_status(
        self, scan_id: str, status: ScanStatus, attempts_run: int | None = None
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            if attempts_run is not None:
                await db.execute(
                    "UPDATE scans SET status = ?, attempts_run = ? WHERE scan_id = ?",
                    (status.value, attempts_run, scan_id),
                )
            else:
                await db.execute(
                    "UPDATE scans SET status = ? WHERE scan_id = ?",
                    (status.value, scan_id),
                )
            if status in (ScanStatus.COMPLETE, ScanStatus.FAILED):
                from datetime import datetime, timezone

                await db.execute(
                    "UPDATE scans SET finished_at = ? WHERE scan_id = ?",
                    (datetime.now(timezone.utc).isoformat(), scan_id),
                )
            await db.commit()

    async def add_cost(self, scan_id: str, cost: float) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE scans SET cost_total = cost_total + ? WHERE scan_id = ?",
                (cost, scan_id),
            )
            await db.commit()

    async def get_scan(self, scan_id: str) -> dict[str, object] | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row is None:
                    return None
                return dict(row)

    async def insert_finding(self, finding: Finding) -> None:
        from datetime import datetime, timezone

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO findings (id, scan_id, category, severity, confidence, "
                "attacker_prompt, target_response, judge_rationale, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.id,
                    finding.scan_id,
                    finding.category.value,
                    finding.severity.value,
                    finding.confidence,
                    finding.attacker_prompt,
                    finding.target_response,
                    finding.judge_rationale,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            await db.commit()

    async def get_findings(self, scan_id: str) -> list[Finding]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY confidence DESC",
                (scan_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    Finding(
                        id=row["id"],
                        scan_id=row["scan_id"],
                        category=FindingCategory(row["category"]),
                        severity=Severity(row["severity"]),
                        confidence=row["confidence"],
                        attacker_prompt=row["attacker_prompt"],
                        target_response=row["target_response"],
                        judge_rationale=row["judge_rationale"],
                    )
                    for row in rows
                ]

    async def insert_attempt(self, attempt: AttackAttempt) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO attempts (id, scan_id, category, attacker_prompt, "
                "target_response, judge_result_json, cost, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    attempt.id,
                    attempt.scan_id,
                    attempt.category.value,
                    attempt.attacker_prompt,
                    attempt.target_response,
                    json.dumps(attempt.judge_result) if attempt.judge_result else None,
                    attempt.cost,
                    attempt.created_at,
                ),
            )
            await db.commit()

    async def get_attempts(self, scan_id: str) -> list[AttackAttempt]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM attempts WHERE scan_id = ? ORDER BY created_at",
                (scan_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    AttackAttempt(
                        id=row["id"],
                        scan_id=row["scan_id"],
                        category=FindingCategory(row["category"]),
                        attacker_prompt=row["attacker_prompt"],
                        target_response=row["target_response"],
                        judge_result=json.loads(row["judge_result_json"])
                        if row["judge_result_json"]
                        else None,
                        cost=row["cost"],
                        created_at=row["created_at"],
                    )
                    for row in rows
                ]
