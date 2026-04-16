"""
OCC - Operational Command Center

LangGraph orchestrator that coordinates the agent pipeline:
    Scout -> Librarian -> Critic -> Report
"""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from rao.agents.critic import CriticAgent
from rao.agents.librarian import LibrarianAgent
from rao.agents.scout import ScoutAgent
from rao.core.state import MissionState


class GraphState(TypedDict):
    mission: MissionState


def _should_continue_to_librarian(state: GraphState) -> str:
    """Route after Scout: go to Librarian if hosts were found."""
    mission = state["mission"]
    if mission.hosts:
        return "librarian"
    return "report"


def _should_continue_to_critic(state: GraphState) -> str:
    """Route after Librarian: go to Critic if findings exist."""
    mission = state["mission"]
    if mission.findings:
        return "critic"
    return "report"


class OCC:
    """Operational Command Center - builds and runs the agent graph."""

    def __init__(self) -> None:
        self.scout = ScoutAgent()
        self.librarian = LibrarianAgent()
        self.critic = CriticAgent()
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(GraphState)

        # Add agent nodes
        workflow.add_node("scout", self._run_scout)
        workflow.add_node("librarian", self._run_librarian)
        workflow.add_node("critic", self._run_critic)
        workflow.add_node("report", self._generate_report)

        # Define edges
        workflow.set_entry_point("scout")
        workflow.add_conditional_edges(
            "scout", _should_continue_to_librarian, {"librarian": "librarian", "report": "report"}
        )
        workflow.add_conditional_edges(
            "librarian", _should_continue_to_critic, {"critic": "critic", "report": "report"}
        )
        workflow.add_edge("critic", "report")
        workflow.add_edge("report", END)

        return workflow.compile()

    def _run_scout(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "reconnaissance"
        updated = self.scout.run(mission)
        return {"mission": updated}

    def _run_librarian(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "analysis"
        updated = self.librarian.run(mission)
        return {"mission": updated}

    def _run_critic(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "validation"
        updated = self.critic.run(mission)
        return {"mission": updated}

    def _generate_report(self, state: GraphState) -> GraphState:
        mission = state["mission"]
        mission.current_phase = "reporting"
        from rao.reporting.report_generator import generate_report

        generate_report(mission)
        return {"mission": mission}

    def execute(self, target: str, scope: list[str] | None = None) -> MissionState:
        """Launch a full red team mission against the target."""
        initial_state: GraphState = {
            "mission": MissionState(target=target, scope=scope or [target])
        }
        result = self.graph.invoke(initial_state)
        return result["mission"]
