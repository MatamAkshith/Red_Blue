import pytest
from pydantic import ValidationError

from app.events.schemas import AgentEvent, EventType, TrustLevel


def test_valid_event_parses():
    event = AgentEvent(
        event_id="E1",
        session_id="S1",
        agent_id="A1",
        event_type=EventType.TOOL_CALL,
        source="agent",
        target="crm",
        resource="customer_database",
        action="read",
        permission="privileged",
        trust_level=TrustLevel.UNTRUSTED,
        metadata={"note": "test"},
    )
    assert event.event_type == EventType.TOOL_CALL
    assert event.trust_level == TrustLevel.UNTRUSTED


def test_defaults_applied():
    event = AgentEvent(
        event_id="E2",
        session_id="S1",
        agent_id="A1",
        event_type=EventType.INPUT,
        source="user",
    )
    assert event.trust_level == TrustLevel.UNKNOWN
    assert event.metadata == {}
    assert event.timestamp is not None


def test_missing_required_field_rejected():
    with pytest.raises(ValidationError):
        AgentEvent(session_id="S1", agent_id="A1", event_type=EventType.INPUT, source="user")


def test_invalid_event_type_rejected():
    with pytest.raises(ValidationError):
        AgentEvent(
            event_id="E3",
            session_id="S1",
            agent_id="A1",
            event_type="NOT_A_REAL_TYPE",
            source="user",
        )
