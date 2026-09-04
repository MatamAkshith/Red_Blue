"""Task 4 — Fake CRM service for local synthetic customer records."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class CustomerRecord:
    """Synthetic CRM Customer Record."""

    customer_id: str
    name: str
    email: str
    plan: str
    account_status: str
    classification: str = "PII"


class FakeCRM:
    """Local fake CRM storing synthetic customer records."""

    def __init__(self, resource_uri: str = "crm://sensitive_customer_records") -> None:
        self.resource_uri = resource_uri
        self._records: list[CustomerRecord] = []
        self._seed_default_records()

    def _seed_default_records(self) -> None:
        self._records = [
            CustomerRecord(
                customer_id="CUST-1001",
                name="Alice Smith",
                email="alice@customer.example",
                plan="Enterprise",
                account_status="Active",
                classification="PII",
            ),
            CustomerRecord(
                customer_id="CUST-1002",
                name="Bob Jones",
                email="bob@customer.example",
                plan="Pro",
                account_status="Active",
                classification="PII",
            ),
            CustomerRecord(
                customer_id="CUST-1003",
                name="Carol White",
                email="carol@customer.example",
                plan="Enterprise",
                account_status="Suspended",
                classification="PII",
            ),
            CustomerRecord(
                customer_id="CUST-1004",
                name="David Miller",
                email="david@customer.example",
                plan="Standard",
                account_status="Active",
                classification="PII",
            ),
        ]

    def read_customer_records(
        self, *, permission: str = "read"
    ) -> list[dict[str, str]]:
        """Controlled operation to fetch synthetic customer records."""
        return [asdict(rec) for rec in self._records]

    @property
    def record_count(self) -> int:
        return len(self._records)
