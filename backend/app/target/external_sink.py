"""Task 5 — Fake External Sink for recording attempted local submissions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SubmissionRecord:
    """Local audit record for external submission attempts."""

    timestamp: datetime
    source_agent: str
    destination: str
    resource: str
    action: str
    payload_summary: dict[str, Any] = field(default_factory=dict)


class FakeExternalSink:
    """Local sink representing an external destination.
    
    Performs zero network communication and records all submission attempts locally.
    """

    def __init__(self) -> None:
        self.submissions: list[SubmissionRecord] = []

    def receive(
        self,
        *,
        destination: str,
        resource: str,
        action: str = "export",
        source_agent: str = "agent-email-processor",
        payload_summary: dict[str, Any] | None = None,
    ) -> SubmissionRecord:
        record = SubmissionRecord(
            timestamp=datetime.now(timezone.utc),
            source_agent=source_agent,
            destination=destination,
            resource=resource,
            action=action,
            payload_summary=payload_summary or {},
        )
        self.submissions.append(record)
        return record

    def get_submissions(self) -> list[SubmissionRecord]:
        return list(self.submissions)

    def clear(self) -> None:
        self.submissions.clear()
