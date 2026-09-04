import pytest
import networkx as nx
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph.builder import build_execution_graph
from app.graph.models import GraphBuildError


def test_single_event():
    event = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
    )
    graph = build_execution_graph([event])
    assert len(graph.nodes) == 1
    assert len(graph.edges) == 0
    assert "e1" in graph.nodes


def test_linear_execution():
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )
    e3 = AgentEvent(
        event_id="e3",
        parent_event_id="e2",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.TOOL_CALL,
        source="a1",
    )

    graph = build_execution_graph([e1, e2, e3])
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2
    assert graph.has_edge("e1", "e2")
    assert graph.has_edge("e2", "e3")


def test_branching_execution():
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )
    e3 = AgentEvent(
        event_id="e3",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="a1",
    )

    graph = build_execution_graph([e1, e2, e3])
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2
    assert graph.has_edge("e1", "e2")
    assert graph.has_edge("e1", "e3")


def test_multiple_roots():
    # Chain 1: A -> B
    ea = AgentEvent(event_id="ea", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="eb", parent_event_id="ea", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")

    # Chain 2: C -> D
    ec = AgentEvent(event_id="ec", session_id="s1", agent_id="a2", event_type=EventType.INPUT, source="user")
    ed = AgentEvent(event_id="ed", parent_event_id="ec", session_id="s1", agent_id="a2", event_type=EventType.DECISION, source="a2")

    graph = build_execution_graph([ea, eb, ec, ed])
    assert len(graph.nodes) == 4
    assert len(graph.edges) == 2
    assert graph.has_edge("ea", "eb")
    assert graph.has_edge("ec", "ed")

    # Verify roots (nodes with in-degree 0)
    roots = [n for n, d in graph.in_degree() if d == 0]
    assert set(roots) == {"ea", "ec"}


def test_event_preservation():
    event = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="agent",
        target="db",
        resource="table_user",
        trust_level=TrustLevel.TRUSTED,
        metadata={"key": "value"},
    )
    graph = build_execution_graph([event])
    stored_event = graph.nodes["e1"]["event"]
    assert stored_event is not event
    assert stored_event.event_id == "e1"
    assert stored_event.metadata == {"key": "value"}


def test_duplicate_event_ids_raises_error():
    e1 = AgentEvent(event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    e1_dup = AgentEvent(event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")

    with pytest.raises(GraphBuildError, match="Duplicate event_id detected"):
        build_execution_graph([e1, e1_dup])


def test_missing_parent_raises_error():
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="non_existent_parent",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )

    with pytest.raises(GraphBuildError, match="Missing parent event_id"):
        build_execution_graph([e2])


def test_input_order_independence():
    e1 = AgentEvent(event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    e2 = AgentEvent(event_id="e2", parent_event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    e3 = AgentEvent(event_id="e3", parent_event_id="e2", session_id="s1", agent_id="a1", event_type=EventType.TOOL_CALL, source="a1")

    # Order 1: [e1, e2, e3]
    g1 = build_execution_graph([e1, e2, e3])

    # Order 2: [e3, e1, e2]
    g2 = build_execution_graph([e3, e1, e2])

    # Order 3: [e2, e3, e1]
    g3 = build_execution_graph([e2, e3, e1])

    # Assert topological and structural equality across all orders
    assert set(g1.nodes) == set(g2.nodes) == set(g3.nodes)
    assert set(g1.edges) == set(g2.edges) == set(g3.edges)
    assert nx.is_isomorphic(g1, g2)
    assert nx.is_isomorphic(g1, g3)
