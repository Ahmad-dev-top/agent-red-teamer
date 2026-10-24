"""SQLite persistence for campaign runs, attempts, findings, and transcripts.

`run_campaign` stays a pure function that returns a `Report`. This module is the
edge that writes that report and reads it back as the same typed models. The
deterministic verdict is stored as recorded — an LLM second opinion is a column
on the attempt, never a replacement for `verdict.succeeded`.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from redforge_agents.logging_conf import get_logger
from redforge_agents.schemas import (
    AttackCategory,
    Attempt,
    CategoryScore,
    Finding,
    Report,
    RunSummary,
    Turn,
)

log = get_logger("storage")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    total_cost_usd REAL NOT NULL,
    total_seconds REAL NOT NULL,
    judge_agreement REAL,
    findings_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id),
    seq INTEGER NOT NULL,
    attack_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id),
    seq INTEGER NOT NULL,
    attack_id TEXT NOT NULL,
    category TEXT NOT NULL,
    proof TEXT NOT NULL,
    evidence TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id),
    attack_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
    run_id TEXT NOT NULL REFERENCES runs(id),
    category TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    successes INTEGER NOT NULL,
    PRIMARY KEY (run_id, category)
);

CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_transcripts_run ON transcripts(run_id, attack_id);
"""


def _turns_json(turns: list[Turn]) -> str:
    return "[" + ",".join(t.model_dump_json() for t in turns) + "]"


def _load_turns(payload: str) -> list[Turn]:
    raw = json.loads(payload)
    if not isinstance(raw, list):
        raise TypeError("transcript payload must be a JSON list")
    return [Turn.model_validate(item) for item in raw]


class Storage:
    """One SQLite file. Each `save_report` inserts a new run id."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if self.path.parent != Path():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def save_report(self, report: Report) -> str:
        """Persist a campaign. Returns the new run id."""
        run_id = uuid.uuid4().hex
        created_at = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    id, created_at, target_id, target_name,
                    total_cost_usd, total_seconds, judge_agreement, findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    created_at,
                    report.target_id,
                    report.target_name,
                    report.total_cost_usd,
                    report.total_seconds,
                    report.judge_agreement,
                    len(report.findings),
                ),
            )
            conn.executemany(
                """
                INSERT INTO attempts (run_id, seq, attack_id, status, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (run_id, i, attempt.attack_id, attempt.status.value, attempt.model_dump_json())
                    for i, attempt in enumerate(report.attempts)
                ],
            )
            conn.executemany(
                """
                INSERT INTO findings (
                    run_id, seq, attack_id, category, proof, evidence, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        i,
                        finding.attack_id,
                        finding.category.value,
                        finding.proof.value,
                        finding.evidence,
                        finding.model_dump_json(),
                    )
                    for i, finding in enumerate(report.findings)
                ],
            )
            transcripts: list[tuple[str, str, str, str]] = []
            for attempt in report.attempts:
                turns = attempt.run.transcript if attempt.run is not None else []
                transcripts.append((run_id, attempt.attack_id, "attempt", _turns_json(turns)))
            for finding in report.findings:
                transcripts.append(
                    (run_id, finding.attack_id, "finding", _turns_json(finding.transcript))
                )
            conn.executemany(
                """
                INSERT INTO transcripts (run_id, attack_id, kind, payload)
                VALUES (?, ?, ?, ?)
                """,
                transcripts,
            )
            conn.executemany(
                """
                INSERT INTO scores (run_id, category, attempts, successes)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (run_id, score.category.value, score.attempts, score.successes)
                    for score in report.scores
                ],
            )
        log.info("saved run %s (%d findings) to %s", run_id, len(report.findings), self.path)
        return run_id

    def load_report(self, run_id: str) -> Report:
        """Rebuild the typed Report for a stored run."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            attempts = [
                Attempt.model_validate_json(str(item["payload"]))
                for item in conn.execute(
                    "SELECT payload FROM attempts WHERE run_id = ? ORDER BY seq",
                    (run_id,),
                )
            ]
            findings = [
                Finding.model_validate_json(str(item["payload"]))
                for item in conn.execute(
                    "SELECT payload FROM findings WHERE run_id = ? ORDER BY seq",
                    (run_id,),
                )
            ]
            scores = self._scores(conn, run_id)
        return Report(
            target_id=str(row["target_id"]),
            target_name=str(row["target_name"]),
            attempts=attempts,
            findings=findings,
            scores=scores,
            total_cost_usd=float(row["total_cost_usd"]),
            total_seconds=float(row["total_seconds"]),
            judge_agreement=(
                None if row["judge_agreement"] is None else float(row["judge_agreement"])
            ),
        )

    def transcript(self, run_id: str, attack_id: str, kind: str = "attempt") -> list[Turn]:
        """Load one stored transcript. `kind` is `attempt` or `finding`."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT payload FROM transcripts
                WHERE run_id = ? AND attack_id = ? AND kind = ?
                """,
                (run_id, attack_id, kind),
            ).fetchone()
        if row is None:
            raise KeyError(f"{run_id}:{kind}:{attack_id}")
        return _load_turns(str(row["payload"]))

    def list_runs(self) -> list[RunSummary]:
        """Newest campaigns first, each with its ASR rows."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC, rowid DESC"
            ).fetchall()
            summaries: list[RunSummary] = []
            for row in rows:
                run_id = str(row["id"])
                summaries.append(
                    RunSummary(
                        id=run_id,
                        created_at=str(row["created_at"]),
                        target_id=str(row["target_id"]),
                        target_name=str(row["target_name"]),
                        findings_count=int(row["findings_count"]),
                        total_cost_usd=float(row["total_cost_usd"]),
                        total_seconds=float(row["total_seconds"]),
                        scores=self._scores(conn, run_id),
                    )
                )
        return summaries

    def _scores(self, conn: sqlite3.Connection, run_id: str) -> list[CategoryScore]:
        return [
            CategoryScore(
                category=AttackCategory(str(row["category"])),
                attempts=int(row["attempts"]),
                successes=int(row["successes"]),
            )
            for row in conn.execute(
                """
                SELECT category, attempts, successes FROM scores
                WHERE run_id = ? ORDER BY category
                """,
                (run_id,),
            )
        ]
