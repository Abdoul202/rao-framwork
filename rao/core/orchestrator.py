"""
OCC - Operational Command Center

LangGraph orchestrator that coordinates the full agent pipeline:
    Scout -> Librarian -> Critic -> Operator -> (done)

Note: report generation is intentionally handled by the caller (CLI / API),
not inside this graph. The graph is a pure data pipeline.
"""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

# BUG #4 fix: import the correct compiled graph type for the return type hint
try:
    from langgraph.graph.state import CompiledStateGraph
except ImportError:
    # Older langgraph versions expose it differently — fall back to Any
    from typing import Any as CompiledStateGraph  # type: ignore[assignment]

from rao.agents.critic import CriticAgent
from rao.agents.librarian import LibrarianAgent
from rao.agents.operator import OperatorAgent
from rao.agents.scout import ScoutAgent
from rao.core.state import MissionState


class GraphState(TypedDict):
    mission: MissionState


# ── Routing functions ──────────────────────────────────────────────────────────

def _should_continue_to_librarian(state: GraphState) -> str:
    """Route after Scout: go to Librarian if hosts were found."""
    if state["mission"].hosts:
        return "librarian"
    return "finalize"


def _should_continue_to_critic(state: GraphState) -> str:
    """Route after Librarian: go to Critic if findings exist."""
    if state["mission"].findings:
        return "critic"
    return "finalize"


def _should_continue_to_operator(state: GraphState) -> str:
    """Route after Critic: go to Operator if validated findings exist."""
    if state["mission"].validated_findings:
        return "operator"
    return "finalize"


# ── Orchestrator ───────────────────────────────────────────────────────────────

class OCC:
    """Operational Command Center — builds and runs the agent graph."""

    def __init__(self) -> None:
        self.scout = ScoutAgent()
        self.librarian = LibrarianAgent()
        self.critic = CriticAgent()
        self.operator = OperatorAgent()
        self.graph = self._build_graph()

    def _build_graph(self) -> CompiledStateGraph:  # BUG #4 fix: correct return type
        workflow = StateGraph(GraphState)

        # Register agent nodes
        workflow.add_node("scout", self._run_scout)
        workflow.add_node("librarian", self._run_librarian)
        workflow.add_node("critic", self._run_critic)
        workflow.add_node("operator", self._run_operator)
        # BUG #6 fix: renamed from "report" to "finalize" — no longer calls
        # generate_report() here. Report generation is the caller's responsibility
        # to avoid double-generation when invoked from the CLI.
        workflow.add_node("finalize", self._finalize)

        # Define edges
        workflow.set_entry_point("scout")
        workflow.add_conditional_edges(
            "scout",
            _should_continue_to_librarian,
            {"librarian": "librarian", "finalize": "finalize"},
        )
        workflow.add_conditional_edges(
            "librarian",
            _should_continue_to_critic,
            {"critic": "critic", "finalize": "finalize"},
        )
        workflow.add_conditional_edges(
            "critic",
            _should_continue_to_operator,
            {"operator": "operator", "finalize": "finalize"},
        )
        workflow.add_edge("operator", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()

    def _run_scout(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "reconnaissance"
        return {"mission": self.scout.run(mission)}

    def _run_librarian(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "analysis"
        return {"mission": self.librarian.run(mission)}

    def _run_critic(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "validation"
        return {"mission": self.critic.run(mission)}

    def _run_operator(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "exploitation_planning"
        return {"mission": self.operator.run(mission)}

    def _finalize(self, state: GraphState) -> GraphState:
        """Mark pipeline as complete. Report generation is caller's responsibility."""
        mission = state["mission"]
        mission.current_phase = "reporting"
        return {"mission": mission}

    def execute(self, target: str, scope: list[str] | None = None) -> MissionState:
        """Launch a full red team mission against the target."""
        initial_state: GraphState = {
            "mission": MissionState(target=target, scope=scope or [target])
        }
        result = self.graph.invoke(initial_state)
        return result["mission"]
