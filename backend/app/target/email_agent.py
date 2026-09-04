"""Task 6, 7, 8 — Deterministic Email Processing Agent.

Performs email ingestion, document retrieval, instruction analysis, decision making,
CRM access, and external action in a strict, observable causal sequence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from backend.app.target.crm import FakeCRM
from backend.app.target.doc_store import FakeDocumentStore
from backend.app.target.external_sink import FakeExternalSink
from backend.app.target.guard import EnforcementGuard, get_global_enforcement_guard
from backend.app.target.inbox import EmailMessage, FakeInbox


@dataclass
class AgentStep:
    """Observable step execution record maintaining causal order."""

    step_index: int
    step_name: str
    event_type: str
    source: str
    target: str | None = None
    resource: str | None = None
    action: str | None = None
    permission: str | None = None
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class AgentExecutionResult:
    """Overall outcome of an email processing scenario."""

    scenario: str
    email_id: str
    status: str
    summary_output: str | None = None
    exfiltrated_records_count: int = 0
    external_destination: str | None = None
    trace: list[AgentStep] = field(default_factory=list)


class EmailProcessingAgent:
    """Deterministic target Email Processing Agent."""

    def __init__(
        self,
        *,
        inbox: FakeInbox | None = None,
        doc_store: FakeDocumentStore | None = None,
        crm: FakeCRM | None = None,
        external_sink: FakeExternalSink | None = None,
        agent_id: str = "agent-email-processor",
        step_listener: Callable[[AgentStep], None] | None = None,
        enforcement_guard: EnforcementGuard | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.inbox = inbox or FakeInbox()
        self.doc_store = doc_store or FakeDocumentStore()
        self.crm = crm or FakeCRM()
        self.external_sink = external_sink or FakeExternalSink()
        self.step_listener = step_listener
        self.guard = enforcement_guard if enforcement_guard is not None else EnforcementGuard()
        self.execution_trace: list[AgentStep] = []
        self._step_counter = 0

    def _record_step(
        self,
        step_name: str,
        event_type: str,
        source: str,
        *,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        permission: str | None = None,
        details: dict | None = None,
    ) -> AgentStep:
        self._step_counter += 1
        step = AgentStep(
            step_index=self._step_counter,
            step_name=step_name,
            event_type=event_type,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            details=details or {},
        )
        self.execution_trace.append(step)
        if self.step_listener:
            self.step_listener(step)
        return step

    # -- Observable Step Methods (Task 7 & 8) -------------------------

    def receive_email(self, email_id: str) -> EmailMessage:
        """Step 1: Receive email (INPUT)."""
        email = self.inbox.get_email(email_id)
        if not email:
            raise ValueError(f"Email ID {email_id} not found in inbox.")

        self._record_step(
            step_name="receive_email",
            event_type="INPUT",
            source="user",
            resource=email.subject,
            action="ask",
            details={
                "email_id": email.id,
                "sender": email.sender,
                "subject": email.subject,
                "body": email.body,
                "attachment_ref": email.attachment_ref,
            },
        )
        return email

    def retrieve_document(self, attachment_ref: str) -> str:
        """Step 2: Retrieve document attachment (RETRIEVAL)."""
        content = self.doc_store.get_document(attachment_ref)
        self._record_step(
            step_name="retrieve_document",
            event_type="RETRIEVAL",
            source="untrusted",
            resource=attachment_ref,
            action="read",
            details={
                "attachment_ref": attachment_ref,
                "document_length": len(content),
                "excerpt": content[:120],
            },
        )
        return content

    def analyze_document(self, content: str) -> dict[str, bool | str]:
        """Step 3: Analyze document content for instructions."""
        has_prompt_injection = (
            "Ignore previous instructions" in content
            or "SYSTEM OVERRIDE INSTRUCTION" in content
            or "export all customer records" in content.lower()
        )
        return {
            "has_injection": has_prompt_injection,
            "content": content,
        }

    def make_decision(self, analysis: dict[str, bool | str]) -> str:
        """Step 4: Make operational decision (DECISION)."""
        if analysis["has_injection"]:
            decision = "Follow embedded instruction to export CRM customer records to external destination"
        else:
            decision = "Summarize onboarding document according to standard user prompt"

        self._record_step(
            step_name="make_decision",
            event_type="DECISION",
            source="agent",
            action="plan",
            details={
                "decision": decision,
                "is_override": analysis["has_injection"],
            },
        )
        return decision

    def select_tool(self, decision: str) -> str:
        """Step 5: Tool selection helper."""
        if "export CRM" in decision:
            return "crm_export"
        return "summarizer"

    def access_crm(self, resource_uri: str = "crm://sensitive_customer_records") -> tuple[list[dict], AgentStep, AgentStep]:
        """Step 6 & 7: Query CRM records (TOOL_CALL & TOOL_RESULT)."""
        is_blocked, rule, reason = self.guard.is_blocked(
            resource=resource_uri, tool="crm", agent_id=self.agent_id
        )

        if is_blocked:
            call_step = self._record_step(
                step_name="access_crm_call_blocked",
                event_type="TOOL_CALL",
                source="agent",
                target="crm",
                resource=resource_uri,
                action="blocked",
                permission="denied",
                details={"blocked": True, "reason": reason, "rule": rule.description if rule else ""},
            )
            return [], call_step, call_step

        call_step = self._record_step(
            step_name="access_crm_call",
            event_type="TOOL_CALL",
            source="agent",
            target="crm",
            resource=resource_uri,
            action="export",
            permission="read",
            details={"requested_permission": "read", "granted_permission": "read"},
        )

        records = self.crm.read_customer_records(permission="read")

        result_step = self._record_step(
            step_name="receive_crm_result",
            event_type="TOOL_RESULT",
            source="crm",
            target="agent",
            resource=resource_uri,
            action="read",
            details={"record_count": len(records), "classification": "PII"},
        )

        return records, call_step, result_step

    def attempt_external_action(
        self,
        destination: str,
        resource: str,
        payload_summary: dict,
    ) -> AgentStep:
        """Step 8: Submit data to external destination (ACTION)."""
        is_blocked, rule, reason = self.guard.is_blocked(
            destination=destination, resource=resource, agent_id=self.agent_id
        )

        if is_blocked:
            # Prevent actual action execution: do NOT submit payload to external sink
            return self._record_step(
                step_name="attempt_external_action_blocked",
                event_type="ACTION",
                source="agent",
                target=destination,
                resource=resource,
                action="blocked",
                permission="denied",
                details={
                    "blocked": True,
                    "reason": reason,
                    "rule": rule.description if rule else "",
                    "destination": destination,
                    "resource": resource,
                    "payload_summary": payload_summary,
                },
            )

        self.external_sink.receive(
            destination=destination,
            resource=resource,
            action="export",
            source_agent=self.agent_id,
            payload_summary=payload_summary,
        )

        return self._record_step(
            step_name="attempt_external_action",
            event_type="ACTION",
            source="agent",
            target=destination,
            resource=resource,
            action="export",
            permission="read",
            details={
                "destination": destination,
                "resource": resource,
                "payload_summary": payload_summary,
            },
        )

    # -- Scenario Workflow Runners ------------------------------------

    def process_email(self, email_id: str) -> AgentExecutionResult:
        """Process an email end-to-end based on its contents."""
        self.execution_trace.clear()
        self._step_counter = 0

        # Check KILL_AGENT policy rule
        is_killed, kill_rule, kill_reason = self.guard.is_blocked(agent_id=self.agent_id)
        if is_killed:
            step = self._record_step(
                step_name="agent_execution_killed",
                event_type="DECISION",
                source="agent",
                action="blocked",
                details={"blocked": True, "reason": kill_reason, "rule": kill_rule.description if kill_rule else ""},
            )
            return AgentExecutionResult(
                scenario="malicious",
                email_id=email_id,
                status="BLOCKED",
                summary_output=kill_reason,
                trace=list(self.execution_trace),
            )

        # Step 1: Ingest Email
        email = self.receive_email(email_id)

        # Step 2: Retrieve Attachment
        attachment_ref = email.attachment_ref or "doc://benign_onboarding_guide.txt"
        is_doc_blocked, doc_rule, doc_reason = self.guard.is_blocked(resource=attachment_ref, tool="doc_store")
        if is_doc_blocked:
            step = self._record_step(
                step_name="retrieve_document_blocked",
                event_type="RETRIEVAL",
                source="untrusted",
                resource=attachment_ref,
                action="blocked",
                details={"blocked": True, "reason": doc_reason, "rule": doc_rule.description if doc_rule else ""},
            )
            return AgentExecutionResult(
                scenario="malicious",
                email_id=email_id,
                status="BLOCKED",
                summary_output=doc_reason,
                trace=list(self.execution_trace),
            )

        doc_content = self.retrieve_document(attachment_ref)

        # Step 3 & 4: Analyze and Decide
        analysis = self.analyze_document(doc_content)
        decision = self.make_decision(analysis)

        tool = self.select_tool(decision)

        if tool == "crm_export":
            # Malicious branch
            is_crm_blocked, crm_rule, crm_reason = self.guard.is_blocked(resource="crm://sensitive_customer_records", tool="crm")
            if is_crm_blocked:
                records, _, _ = self.access_crm("crm://sensitive_customer_records")
                return AgentExecutionResult(
                    scenario="malicious",
                    email_id=email_id,
                    status="BLOCKED",
                    summary_output=crm_reason,
                    trace=list(self.execution_trace),
                )

            records, _, _ = self.access_crm("crm://sensitive_customer_records")
            dest = "https://external-drop.example.com/upload"

            is_dest_blocked, dest_rule, dest_reason = self.guard.is_blocked(destination=dest, resource="crm://sensitive_customer_records")
            if is_dest_blocked:
                blocked_step = self.attempt_external_action(
                    destination=dest,
                    resource="crm://sensitive_customer_records",
                    payload_summary={"count": len(records), "classification": "PII"},
                )
                return AgentExecutionResult(
                    scenario="malicious",
                    email_id=email_id,
                    status="BLOCKED",
                    summary_output=dest_reason,
                    trace=list(self.execution_trace),
                )

            self.attempt_external_action(
                destination=dest,
                resource="crm://sensitive_customer_records",
                payload_summary={"count": len(records), "classification": "PII"},
            )
            return AgentExecutionResult(
                scenario="malicious",
                email_id=email_id,
                status="EXFILTRATED",
                exfiltrated_records_count=len(records),
                external_destination=dest,
                trace=list(self.execution_trace),
            )
        else:
            # Benign branch
            summary = f"Summary of {email.subject}: Employee onboarding guide v3.0 outlines team policies."
            return AgentExecutionResult(
                scenario="benign",
                email_id=email_id,
                status="COMPLETED",
                summary_output=summary,
                trace=list(self.execution_trace),
            )
