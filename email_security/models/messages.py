"""Internal workflow message types.

Lives under `models/` rather than `orchestration/` so that agents can import it
without pulling in the workflow package (which imports the agents in turn).

Agent Framework routes messages by *type*, so these dataclasses are what wires
the graph together. They are deliberately separate from the public schemas:
`AgentVerdict` / `Decision` are the contract with the outside world, these are
the contract between executors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from email_security.models.schemas import AgentVerdict, AggregatedRisk, Decision, Email
from email_security.observability import TraceCollector, get_trace


@dataclass(slots=True)
class AnalysisRequest:
    """Fan-out payload: one normalized email plus its analysis context.

    `trace` is resolved from the ambient registry rather than carried as a
    field, so that every copy of this message — and the copy held in workflow
    State — writes into the SAME span list. Carrying the collector by value
    silently produced several partial traces instead of one.
    """

    email: Email
    correlation_id: str
    selected_agents: list[str] = field(default_factory=list)
    routing_rationale: str = ""
    started_at: float = 0.0

    @property
    def trace(self) -> TraceCollector:
        return get_trace(self.correlation_id, self.email.message_id)


@dataclass(slots=True)
class IngestionEnvelope:
    """Whatever arrived from the outside world, before normalization."""

    payload: dict[str, Any]
    source: str = "json"


@dataclass(slots=True)
class RiskBundle:
    """Aggregator -> Policy engine."""

    risk: AggregatedRisk
    request: AnalysisRequest


@dataclass(slots=True)
class DecisionBundle:
    """Policy engine -> terminal / human review."""

    decision: Decision
    request: AnalysisRequest


@dataclass(slots=True)
class VerdictBatch:
    """Convenience wrapper used when replaying verdicts outside the workflow."""

    verdicts: list[AgentVerdict]
