import pytest
from backend.app.events.schemas import AgentEvent, EventType
from backend.app.graph.builder import build_execution_graph
from backend.app.graph.models import GraphValidationError
from backend.app.graph.traversal import (
    get_ancestors,
    get_descendants,
    get_execution_path,
    get_leaf_events,
    get_root_events,
)


@pytest.fixture
def complex_graph():
    """
    Constructs a deterministic complex graph:
    Tree 1:
      r1 -> a1 -> b1
               -> b2 -> c1
    Tree 2:
      r2 -> a2
    """
    events = [
        AgentEvent(event_id="r1", session_id="s1", agent_id="ag1", event_type=EventType.INPUT, source="user"),
        AgentEvent(event_id="a1", parent_event_id="r1", session_id="s1", agent_id="ag1", event_type=EventType.DECISION, source="ag1"),
        AgentEvent(event_id="b1", parent_event_id="a1", session_id="s1", agent_id="ag1", event_type=EventType.TOOL_CALL, source="ag1"),
        AgentEvent(event_id="b2", parent_event_id="a1", session_id="s1", agent_id="ag1", event_type=EventType.RETRIEVAL, source="ag1"),
        AgentEvent(event_id="c1", parent_event_id="b2", session_id="s1", agent_id="ag1", event_type=EventType.ACTION, source="ag1"),

        AgentEvent(event_id="r2", session_id="s1", agent_id="ag2", event_type=EventType.INPUT, source="user"),
        AgentEvent(event_id="a2", parent_event_id="r2", session_id="s1", agent_id="ag2", event_type=EventType.ACTION, source="ag2"),
    ]
    return build_execution_graph(events)


def test_root_detection(complex_graph):
    roots = get_root_events(complex_graph)
    assert roots == ["r1", "r2"]


def test_leaf_detection(complex_graph):
    leaves = get_leaf_events(complex_graph)
    assert leaves == ["a2", "b1", "c1"]


def test_ancestors_linear():
    e1 = AgentEvent(event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="u")
    e2 = AgentEvent(event_id="e2", parent_event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a")
    e3 = AgentEvent(event_id="e3", parent_event_id="e2", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a")
    g = build_execution_graph([e1, e2, e3])

    ancestors = get_ancestors(g, "e3")
    assert ancestors == ["e1", "e2"]


def test_descendants_linear():
    e1 = AgentEvent(event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="u")
    e2 = AgentEvent(event_id="e2", parent_event_id="e1", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a")
    e3 = AgentEvent(event_id="e3", parent_event_id="e2", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a")
    g = build_execution_graph([e1, e2, e3])

    descendants = get_descendants(g, "e1")
    assert descendants == ["e2", "e3"]


def test_branching_ancestors_and_descendants(complex_graph):
    # Descendants of r1: a1, b1, b2, c1
    desc_r1 = get_descendants(complex_graph, "r1")
    assert desc_r1 == ["a1", "b1", "b2", "c1"]

    # Ancestors of c1: r1, a1, b2
    anc_c1 = get_ancestors(complex_graph, "c1")
    assert anc_c1 == ["a1", "b2", "r1"]


def test_multiple_roots_isolation(complex_graph):
    # Tree 1 ancestors do not contain Tree 2 nodes
    anc_a2 = get_ancestors(complex_graph, "a2")
    assert anc_a2 == ["r2"]

    desc_r2 = get_descendants(complex_graph, "r2")
    assert desc_r2 == ["a2"]


def test_valid_execution_path(complex_graph):
    path = get_execution_path(complex_graph, "r1", "c1")
    assert path == ["r1", "a1", "b2", "c1"]


def test_invalid_execution_path_disconnected(complex_graph):
    with pytest.raises(GraphValidationError, match="No execution path exists"):
        get_execution_path(complex_graph, "r1", "a2")


def test_nonexistent_node_raises_validation_error(complex_graph):
    with pytest.raises(GraphValidationError, match="does not exist"):
        get_ancestors(complex_graph, "nonexistent")

    with pytest.raises(GraphValidationError, match="does not exist"):
        get_descendants(complex_graph, "nonexistent")

    with pytest.raises(GraphValidationError, match="does not exist"):
        get_execution_path(complex_graph, "nonexistent", "r1")


def test_deterministic_result_ordering(complex_graph):
    # Execute traversal 100 times to guarantee deterministic sorted list output
    for _ in range(100):
        assert get_root_events(complex_graph) == ["r1", "r2"]
        assert get_leaf_events(complex_graph) == ["a2", "b1", "c1"]
        assert get_descendants(complex_graph, "r1") == ["a1", "b1", "b2", "c1"]
        assert get_ancestors(complex_graph, "c1") == ["a1", "b2", "r1"]
