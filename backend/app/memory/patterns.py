"""Failure-pattern memory.

Persists the `failure_pattern_candidate` P2 produces, keyed by a
*deterministic* signature derived only from P1 facts. Recall therefore
works fully offline -- Featherless is needed to author a pattern, never to
match one.

Historical AgentEvents and security facts are never touched: this store is
append/update-only over its own table.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Collection
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.aegis.models import ImpactResult
from app.detection.models import DetectionFinding
from app.understand.investigation.schemas import FailurePatternCandidate

_SCHEMA = """
CREATE TABLE IF NOT EXISTS failure_patterns (
    signature TEXT PRIMARY KEY,
    pattern_name TEXT NOT NULL,
    description TEXT NOT NULL,
    indicators TEXT NOT NULL,
    provenance TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1
);
"""


class PatternProvenance(BaseModel):
    """Where a stored pattern came from -- enough to trace it back."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    session_id: str
    finding_ids: tuple[str, ...] = Field(default_factory=tuple)
    event_ids: tuple[str, ...] = Field(default_factory=tuple)


class StoredPattern(BaseModel):
    model_config = ConfigDict(frozen=True)

    signature: str
    pattern: FailurePatternCandidate
    provenance: PatternProvenance
    times_seen: int = 1


def compute_signature(
    findings: Collection[DetectionFinding], impacts: Collection[ImpactResult]
) -> str:
    """Abstract shape of the failure, from P1 facts only.

    Deliberately drops incident/session/event identity and concrete
    destinations -- two incidents with the same detector mix, the same
    sensitive-resource exposure and the same external-reach property share
    a signature, which is what makes a pattern reusable.
    """

    detectors = sorted(
        {str(getattr(f.detector_type, "value", f.detector_type)) for f in findings}
    )
    resources = sorted(
        {r.resource for i in impacts for r in i.reachable_sensitive_resources}
    )
    reached_external = any(i.reachable_external_destinations for i in impacts)
    return "|".join(
        [",".join(detectors), ",".join(resources), f"external={reached_external}"]
    )


class FailurePatternStore:
    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def remember(
        self,
        signature: str,
        pattern: FailurePatternCandidate,
        provenance: PatternProvenance,
    ) -> StoredPattern:
        """Store a pattern, or bump its seen-count if the signature is known.

        The first provenance wins: it records where the pattern was
        originally learned.
        """

        existing = self.recall(signature)
        if existing is not None:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE failure_patterns SET times_seen = times_seen + 1 "
                    "WHERE signature = ?",
                    (signature,),
                )
            return existing.model_copy(update={"times_seen": existing.times_seen + 1})

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO failure_patterns "
                "(signature, pattern_name, description, indicators, provenance) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    signature,
                    pattern.pattern_name,
                    pattern.description,
                    json.dumps(list(pattern.indicators)),
                    provenance.model_dump_json(),
                ),
            )
        return StoredPattern(signature=signature, pattern=pattern, provenance=provenance)

    def recall(self, signature: str) -> StoredPattern | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT pattern_name, description, indicators, provenance, times_seen "
                "FROM failure_patterns WHERE signature = ?",
                (signature,),
            ).fetchone()
        if row is None:
            return None

        name, description, indicators, provenance, times_seen = row
        return StoredPattern(
            signature=signature,
            pattern=FailurePatternCandidate(
                pattern_name=name,
                description=description,
                indicators=json.loads(indicators),
            ),
            provenance=PatternProvenance.model_validate_json(provenance),
            times_seen=times_seen,
        )

    def all_patterns(self) -> list[StoredPattern]:
        with self._connect() as conn:
            signatures = [
                r[0]
                for r in conn.execute(
                    "SELECT signature FROM failure_patterns ORDER BY signature"
                ).fetchall()
            ]
        return [p for s in signatures if (p := self.recall(s)) is not None]
