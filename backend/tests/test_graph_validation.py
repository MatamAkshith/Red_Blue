import pytest
import networkx as nx
from app.events.schemas import AgentEvent, EventType
from app.graph.builder import build_execution_graph
from app.graph.models import GraphValidationError
from app.graph.validation import validate_execution_graph


def test_valid_single_event():
    e1 = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    g = build_execution_graph([e1])
    assert validate_execution_graph([e1], g) is True


def test_valid_linear_execution():
    e1 = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    e2 = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    e3 = AgentEvent(event_id="C", parent_event_id="B", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")
    events = [e1, e2, e3]
    g = build_execution_graph(events)
    assert validate_execution_graph(events, g) is True


def test_valid_branching():
    e1 = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    e2 = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    e3 = AgentEvent(event_id="C", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.RETRIEVAL, source="a1")
    events = [e1, e2, e3]
    g = build_execution_graph(events)
    assert validate_execution_graph(events, g) is True


def test_valid_multiple_roots():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", session_id="s1", agent_id="a2", event_type=EventType.INPUT, source="user")
    ed = AgentEvent(event_id="D", parent_event_id="C", session_id="s1", agent_id="a2", event_type=EventType.DECISION, source="a2")
    events = [ea, eb, ec, ed]
    g = build_execution_graph(events)
    assert validate_execution_graph(events, g) is True


def test_invalid_missing_node():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", parent_event_id="B", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")
    events = [ea, eb, ec]
    
    # Manually construct graph missing C
    g = build_execution_graph([ea, eb])

    with pytest.raises(GraphValidationError, match="Node count mismatch|Missing node"):
        validate_execution_graph(events, g)


def test_invalid_unexpected_node():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    events = [ea, eb]

    g = build_execution_graph(events)
    fake_event = AgentEvent(event_id="FAKE", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")
    g.add_node("FAKE", event=fake_event)

    with pytest.raises(GraphValidationError, match="Node count mismatch|Unexpected node"):
        validate_execution_graph(events, g)


def test_invalid_missing_parent_edge():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    events = [ea, eb]

    g = build_execution_graph(events)
    g.remove_edge("A", "B")

    with pytest.raises(GraphValidationError, match="Missing parent edge|Root inconsistency"):
        validate_execution_graph(events, g)


def test_invalid_unexpected_edge():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1") # B has no parent
    events = [ea, eb]

    g = build_execution_graph(events)
    g.add_edge("A", "B") # Artificial edge added

    with pytest.raises(GraphValidationError, match="Unexpected edge|Root inconsistency"):
        validate_execution_graph(events, g)


def test_invalid_cycle():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", parent_event_id="B", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")
    events = [ea, eb, ec]

    g = build_execution_graph(events)
    g.add_edge("C", "A") # Introduce cycle

    with pytest.raises(GraphValidationError, match="Cycle detected"):
        validate_execution_graph(events, g)


def test_invalid_identity_mismatch():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    events = [ea, eb]

    g = build_execution_graph(events)
    # Tamper with node A to contain payload B
    g.nodes["A"]["event"] = eb

    with pytest.raises(GraphValidationError, match="Payload identity mismatch"):
        validate_execution_graph(events, g)
