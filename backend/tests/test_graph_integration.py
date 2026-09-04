import pytest
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph import (
    GraphBuildError,
    GraphValidationError,
    build_execution_graph,
    get_ancestors,
    get_descendants,
    get_execution_path,
    get_leaf_events,
    get_root_events,
    validate_execution_graph,
)


def test_linear_pipeline():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", parent_event_id="B", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")
    events = [ea, eb, ec]

    # Pipeline Step 1: Build graph
    graph = build_execution_graph(events)

    # Pipeline Step 2: Validate graph
    assert validate_execution_graph(events, graph) is True

    # Pipeline Step 3: Traversal assertions
    assert get_root_events(graph) == ["A"]
    assert get_leaf_events(graph) == ["C"]
    assert get_execution_path(graph, "A", "C") == ["A", "B", "C"]


def test_branching_pipeline():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.RETRIEVAL, source="a1")
    events = [ea, eb, ec]

    graph = build_execution_graph(events)
    assert validate_execution_graph(events, graph) is True

    assert get_root_events(graph) == ["A"]
    assert get_leaf_events(graph) == ["B", "C"]
    assert get_descendants(graph, "A") == ["B", "C"]


def test_multiple_root_pipeline():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", session_id="s1", agent_id="a2", event_type=EventType.INPUT, source="user")
    ed = AgentEvent(event_id="D", parent_event_id="C", session_id="s1", agent_id="a2", event_type=EventType.DECISION, source="a2")
    events = [ea, eb, ec, ed]

    graph = build_execution_graph(events)
    assert validate_execution_graph(events, graph) is True

    assert get_root_events(graph) == ["A", "C"]
    assert get_descendants(graph, "A") == ["B"]
    assert get_descendants(graph, "C") == ["D"]
    assert get_ancestors(graph, "B") == ["A"]
    assert get_ancestors(graph, "D") == ["C"]


def test_event_preservation_end_to_end():
    event = AgentEvent(
        event_id="EVT_PRESERVE",
        session_id="sess_preserve",
        agent_id="agent_preserve",
        event_type=EventType.TOOL_CALL,
        source="agent_preserve",
        target="database",
        resource="db://records",
        trust_level=TrustLevel.TRUSTED,
        metadata={"critical_flag": True, "payload_size": 2048},
    )

    graph = build_execution_graph([event])
    assert validate_execution_graph([event], graph) is True

    extracted = graph.nodes["EVT_PRESERVE"]["event"]
    assert extracted is event
    assert extracted.event_id == "EVT_PRESERVE"
    assert extracted.session_id == "sess_preserve"
    assert extracted.metadata == {"critical_flag": True, "payload_size": 2048}


def test_deterministic_ordering_scrambled_input():
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    ec = AgentEvent(event_id="C", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.RETRIEVAL, source="a1")
    ed = AgentEvent(event_id="D", parent_event_id="B", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1")

    # Scrambled input order: [D, C, A, B]
    scrambled_events = [ed, ec, ea, eb]

    graph = build_execution_graph(scrambled_events)
    assert validate_execution_graph(scrambled_events, graph) is True

    descendants_a = get_descendants(graph, "A")
    assert descendants_a == ["B", "C", "D"]

    leaves = get_leaf_events(graph)
    assert leaves == ["C", "D"]


def test_pipeline_rejection():
    # 1. Builder Rejection: Missing parent
    invalid_event = AgentEvent(
        event_id="B", parent_event_id="NON_EXISTENT", session_id="s1", agent_id="a1", event_type=EventType.ACTION, source="a1"
    )
    with pytest.raises(GraphBuildError, match="Missing parent event_id"):
        build_execution_graph([invalid_event])

    # 2. Validator Rejection: Corrupted node identity in graph
    ea = AgentEvent(event_id="A", session_id="s1", agent_id="a1", event_type=EventType.INPUT, source="user")
    eb = AgentEvent(event_id="B", parent_event_id="A", session_id="s1", agent_id="a1", event_type=EventType.DECISION, source="a1")
    events = [ea, eb]

    graph = build_execution_graph(events)
    # Corrupt node identity inside payload
    graph.nodes["A"]["event"] = eb

    with pytest.raises(GraphValidationError, match="Payload identity mismatch"):
        validate_execution_graph(events, graph)
