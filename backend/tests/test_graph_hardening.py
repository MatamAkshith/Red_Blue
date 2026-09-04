import networkx as nx
import pytest

from backend.app.detection import DetectionEngine, DetectionError
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel
from backend.app.graph import GraphBuildError, GraphValidationError, build_execution_graph, get_descendants


def event(
    event_id: str,
    *,
    session_id: str = "session-1",
    parent_event_id: str | None = None,
    metadata: dict | None = None,
) -> AgentEvent:
    return AgentEvent(
        event_id=event_id,
        parent_event_id=parent_event_id,
        session_id=session_id,
        agent_id="agent-1",
        event_type=EventType.DECISION,
        source="agent",
        trust_level=TrustLevel.TRUSTED,
        metadata=metadata or {},
    )


def test_same_session_parent_is_valid():
    graph = build_execution_graph([event("E1"), event("E2", parent_event_id="E1")])

    assert graph.has_edge("E1", "E2")


def test_cross_session_parent_is_rejected():
    with pytest.raises(GraphBuildError, match="Cross-session parent edge"):
        build_execution_graph([
            event("E1", session_id="session-a"),
            event("E2", session_id="session-b", parent_event_id="E1"),
        ])


def test_multiple_independent_sessions_are_valid():
    graph = build_execution_graph([
        event("A1", session_id="session-a"),
        event("A2", session_id="session-a", parent_event_id="A1"),
        event("B1", session_id="session-b"),
        event("B2", session_id="session-b", parent_event_id="B1"),
    ])

    assert set(graph.edges()) == {("A1", "A2"), ("B1", "B2")}


def test_cross_session_parent_in_branching_graph_is_rejected():
    with pytest.raises(GraphBuildError, match="Cross-session parent edge"):
        build_execution_graph([
            event("E1", session_id="session-a"),
            event("E2", session_id="session-a", parent_event_id="E1"),
            event("E3", session_id="session-b", parent_event_id="E1"),
        ])


def test_hidden_cross_session_parent_is_rejected():
    with pytest.raises(GraphBuildError, match="Cross-session parent edge"):
        build_execution_graph([
            event("E1"),
            event("E2", parent_event_id="E1"),
            event("E3", session_id="session-2"),
            event("E4", session_id="session-2", parent_event_id="E3"),
            event("E5", session_id="session-2", parent_event_id="E2"),
        ])


@pytest.mark.parametrize(
    "events",
    [
        [event("E1", parent_event_id="E1")],
        [event("E1", parent_event_id="E2"), event("E2", parent_event_id="E1")],
        [
            event("E1", parent_event_id="E3"),
            event("E2", parent_event_id="E1"),
            event("E3", parent_event_id="E2"),
        ],
        [
            event("ROOT"),
            event("E1", parent_event_id="E4"),
            event("E2", parent_event_id="E1"),
            event("E3", parent_event_id="E2"),
            event("E4", parent_event_id="E3"),
        ],
    ],
)
def test_cycles_are_rejected_by_builder(events):
    with pytest.raises(GraphBuildError, match="Cycle detected"):
        build_execution_graph(events)


def test_detection_rejects_a_hand_built_invalid_graph():
    parent = event("E1", session_id="session-a")
    child = event("E2", session_id="session-b", parent_event_id="E1")
    graph = nx.DiGraph()
    graph.add_node("E1", event=parent)
    graph.add_node("E2", event=child)
    graph.add_edge("E1", "E2")

    with pytest.raises(DetectionError, match="Cross-session parent edge"):
        DetectionEngine().run(graph)


def test_graph_snapshots_events_against_post_build_mutation():
    source = event("E1", metadata={"trust": {"level": "trusted"}})
    graph = build_execution_graph([source])

    source.metadata["trust"]["level"] = "untrusted"
    source.metadata["new_claim"] = True

    stored = graph.nodes["E1"]["event"]
    assert stored.metadata == {"trust": {"level": "trusted"}}


def test_traversal_requires_a_validated_builder_graph():
    graph = nx.DiGraph()
    graph.add_node("E1", event=event("E1"))

    with pytest.raises(GraphValidationError, match="produced and validated"):
        get_descendants(graph, "E1")


def test_valid_branching_multi_root_traversal_remains_deterministic():
    graph = build_execution_graph([
        event("A1"),
        event("A2", parent_event_id="A1"),
        event("B1", session_id="session-2"),
        event("B2", session_id="session-2", parent_event_id="B1"),
    ])

    assert get_descendants(graph, "A1") == ["A2"]
    assert get_descendants(graph, "B1") == ["B2"]
