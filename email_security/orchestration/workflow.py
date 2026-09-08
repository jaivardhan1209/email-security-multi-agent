"""The email-security workflow graph (§2, §11, §12).

    IngestionExecutor
           |
    OrchestratorExecutor
           |  add_fan_out_edges  -> all five specialists start in the SAME superstep
     +-----+-----+-----+-----+
     |     |     |     |     |
   spam  phish malware bec  url          (concurrent; each is Executor + Agent)
     |     |     |     |     |
     +-----+-----+-----+-----+
           |  add_fan_in_edges -> aggregator waits for all, receives list[AgentVerdict]
    RiskAggregatorExecutor
           |
      PolicyExecutor
           |  add_switch_case_edge_group -> conditional routing on the decision
     +-----+------+
     |            |
 HumanReview   DeliveryExecutor        (terminal; both yield a Decision)

Agent Framework concepts demonstrated, in order:
  * `Executor` + `@handler`          — typed graph nodes
  * `WorkflowBuilder`                — declarative topology
  * `add_fan_out_edges`              — real concurrency, one superstep
  * `add_fan_in_edges`               — typed aggregation on list[AgentVerdict]
  * `add_switch_case_edge_group`     — conditional routing (HITL vs delivery)
  * shared `State`                   — context that does not belong on an edge
  * `ctx.request_info` + `@response_handler` — human-in-the-loop
  * `WorkflowEvent` stream           — observability
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agent_framework import Case, Default, Workflow, WorkflowBuilder

from email_security.agents import AGENT_REGISTRY, DetectionAgent
from email_security.config.settings import Settings, get_settings
from email_security.models.llm_provider import LLMProvider, get_llm_provider
from email_security.models.messages import DecisionBundle
from email_security.models.schemas import Decision, Email
from email_security.observability import get_logger
from email_security.orchestration.executors import (
    DeliveryExecutor,
    HumanReviewExecutor,
    IngestionExecutor,
    OrchestratorExecutor,
    PolicyExecutor,
    RiskAggregatorExecutor,
)
from email_security.policy import PolicyEngine

logger = get_logger("workflow")

DEFAULT_AGENTS: tuple[str, ...] = ("spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent")


@dataclass(slots=True)
class PipelineComponents:
    """Handles on every node — useful for tests and for the CLI's --explain."""

    ingestion: IngestionExecutor
    orchestrator: OrchestratorExecutor
    detectors: list[DetectionAgent]
    aggregator: RiskAggregatorExecutor
    policy: PolicyExecutor
    human_review: HumanReviewExecutor
    delivery: DeliveryExecutor
    provider: LLMProvider


def build_components(
    *,
    settings: Settings | None = None,
    provider: LLMProvider | None = None,
    agent_names: Sequence[str] = DEFAULT_AGENTS,
    human_review_mode: str = "queue",
) -> PipelineComponents:
    """Construct every node. Dependency injection lives here and nowhere else."""
    settings = settings or get_settings()
    provider = provider or get_llm_provider(settings)

    unknown = [name for name in agent_names if name not in AGENT_REGISTRY]
    if unknown:
        raise ValueError(f"unknown agent(s): {unknown}. Available: {sorted(AGENT_REGISTRY)}")

    detectors = [AGENT_REGISTRY[name](name, provider=provider, settings=settings) for name in agent_names]
    names = [d.id for d in detectors]

    return PipelineComponents(
        ingestion=IngestionExecutor(),
        orchestrator=OrchestratorExecutor(names, settings=settings, provider=provider),
        detectors=detectors,
        aggregator=RiskAggregatorExecutor(names),
        policy=PolicyExecutor(PolicyEngine(settings)),
        human_review=HumanReviewExecutor(mode=human_review_mode),
        delivery=DeliveryExecutor(),
        provider=provider,
    )


def build_workflow(components: PipelineComponents | None = None, **kwargs: Any) -> tuple[Workflow, PipelineComponents]:
    """Assemble the graph. Returns the workflow and the components it wraps."""
    parts = components or build_components(**kwargs)

    def needs_review(message: DecisionBundle) -> bool:
        return bool(message.decision.requires_human_review)

    builder = (
        WorkflowBuilder(start_executor=parts.ingestion, name="email_security_pipeline")
        .add_edge(parts.ingestion, parts.orchestrator)
        # Fan-out: every detector receives the same AnalysisRequest and runs in
        # the same superstep, so total agent latency is max(), not sum().
        .add_fan_out_edges(parts.orchestrator, list(parts.detectors))
        # Fan-in: the aggregator's handler is typed list[AgentVerdict], so the
        # runtime waits for every branch before invoking it.
        .add_fan_in_edges(list(parts.detectors), parts.aggregator)
        .add_edge(parts.aggregator, parts.policy)
        # Conditional routing: decisions needing an analyst take a different path.
        .add_switch_case_edge_group(
            parts.policy,
            [
                Case(condition=needs_review, target=parts.human_review),
                Default(target=parts.delivery),
            ],
        )
    )
    workflow = builder.build()
    logger.info(
        "Workflow built",
        extra={"fields": {"detectors": [d.id for d in parts.detectors], "provider": parts.provider.name,
                          "model": parts.provider.model_name}},
    )
    return workflow, parts


class EmailSecurityPipeline:
    """Convenience façade over the workflow for callers that just want a Decision."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        provider: LLMProvider | None = None,
        agent_names: Sequence[str] = DEFAULT_AGENTS,
        human_review_mode: str = "queue",
    ) -> None:
        self.settings = settings or get_settings()
        self.components = build_components(
            settings=self.settings, provider=provider, agent_names=agent_names, human_review_mode=human_review_mode
        )
        self.workflow, _ = build_workflow(self.components)
        # A Workflow instance holds per-run state and refuses concurrent runs.
        # The lock makes accidental concurrent use safe (serialised) rather than
        # an error; for real throughput use `PipelinePool`.
        self._lock = asyncio.Lock()

    @property
    def provider(self) -> LLMProvider:
        return self.components.provider

    async def analyze(self, email: Email) -> Decision:
        """Run one message end to end. Raises only on programming errors."""
        started = time.perf_counter()
        async with self._lock:
            result = await self.workflow.run(email)
        outputs = result.get_outputs()
        if not outputs:
            raise RuntimeError(
                "Workflow produced no Decision. Check for a failed executor in the event stream."
            )
        decision: Decision = outputs[-1]
        if not decision.total_latency_ms:
            decision.total_latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return decision

    async def analyze_payload(self, payload: dict[str, Any], source: str = "json") -> Decision:
        """Analyze an un-normalized payload (JSON fixture today, Graph tomorrow)."""
        return await self.analyze(IngestionExecutor.normalize(payload, source=source))

    def visualize(self) -> str:
        """Mermaid diagram of the live graph (§15 — the topology is inspectable)."""
        from agent_framework import WorkflowViz

        return WorkflowViz(self.workflow).to_mermaid()


class PipelinePool:
    """Concurrency wrapper: N independent pipelines sharing one model provider.

    A single Agent Framework `Workflow` carries per-run state and rejects
    concurrent runs on the same instance, which is the right default — a
    workflow is a unit of execution, not a server. Throughput therefore comes
    from running several pipelines, exactly as a production deployment would
    scale out consumer replicas behind a queue.

    The LLM provider (and therefore the model connection) is shared, so the pool
    costs a handful of small Python objects per slot, not a model per slot.
    """

    def __init__(
        self,
        size: int = 4,
        *,
        settings: Settings | None = None,
        provider: LLMProvider | None = None,
        agent_names: Sequence[str] = DEFAULT_AGENTS,
        human_review_mode: str = "queue",
    ) -> None:
        if size < 1:
            raise ValueError("pool size must be >= 1")
        settings = settings or get_settings()
        provider = provider or get_llm_provider(settings)
        self.pipelines = [
            EmailSecurityPipeline(
                settings=settings, provider=provider, agent_names=agent_names, human_review_mode=human_review_mode
            )
            for _ in range(size)
        ]
        self._free: asyncio.Queue[EmailSecurityPipeline] = asyncio.Queue()
        for pipeline in self.pipelines:
            self._free.put_nowait(pipeline)
        self.provider = provider

    async def analyze(self, email: Email) -> Decision:
        pipeline = await self._free.get()
        try:
            return await pipeline.analyze(email)
        finally:
            self._free.put_nowait(pipeline)

    def visualize(self) -> str:
        return self.pipelines[0].visualize()
