"""Non-LLM workflow nodes (§2, §4, §17).

Every executor here is *deterministic*. None of them calls a model. That is the
architectural boundary this project is built to demonstrate:

    LLM agents      -> opinions (scores, techniques, reasons)
    Executors       -> transport, aggregation, policy, escalation
    Tools           -> verified facts
    Workflow        -> concurrency, ordering, failure containment

Agent Framework mapping:
    IngestionExecutor  — start executor; normalizes the external payload
    OrchestratorExecutor — fan-out source; owns routing and shared State
    RiskAggregatorExecutor — fan-in target; typed on list[AgentVerdict]
    PolicyExecutor     — switch-case source; converts scores to an action
    HumanReviewExecutor / DeliveryExecutor — terminal executors that yield output
"""

# NOTE: deliberately no `from __future__ import annotations` in this module.
# Agent Framework resolves handler and response-handler signatures by
# introspection at class-creation time, and string annotations defeat that.

import time
from typing import Any

from agent_framework import Executor, WorkflowContext, handler, response_handler

from email_security.config.settings import Settings, get_settings
from email_security.models.messages import AnalysisRequest, DecisionBundle, IngestionEnvelope, RiskBundle
from email_security.models.schemas import (
    Action,
    AgentVerdict,
    AggregatedRisk,
    Decision,
    Email,
    HumanReviewRequest,
    HumanReviewResponse,
    ThreatClass,
)
from email_security.observability import get_logger, get_trace, new_correlation_id, release_trace, set_correlation_id
from email_security.orchestration.router import DeterministicRouter, LLMRouter
from email_security.policy import CLASS_PRIORITY, PolicyEngine

logger = get_logger("orchestration")

STATE_REQUEST_KEY = "analysis_request"

#: A malware score at or above this is treated as a confirmed payload, which
#: takes precedence over whatever social-engineering pretext carried it.
CONFIRMED_PAYLOAD_SCORE = 0.85

#: Which agent's score answers for which threat class, and the aggregate key.
AGENT_SCORE_KEYS: dict[str, str] = {
    "spam_agent": "spam_score",
    "phishing_agent": "phishing_score",
    "malware_agent": "malware_score",
    "bec_agent": "bec_score",
    "url_agent": "url_score",
}


# --------------------------------------------------------------------------- #
# Ingestion (§9 — the seam Microsoft Graph plugs into)
# --------------------------------------------------------------------------- #


class IngestionExecutor(Executor):
    """Normalizes whatever arrived into the canonical `Email` model.

    Today it accepts a JSON dict or an already-built `Email`. A Graph-backed
    deployment adds one branch here that maps a Graph `message` resource onto
    the same model — no other component changes.
    """

    def __init__(self, executor_id: str = "ingestion") -> None:
        super().__init__(id=executor_id)
        self._seen: dict[str, float] = {}

    @handler
    async def from_envelope(self, envelope: IngestionEnvelope, ctx: WorkflowContext[AnalysisRequest]) -> None:
        email = self.normalize(envelope.payload, source=envelope.source)
        await ctx.send_message(self._to_request(email))

    @handler
    async def from_email(self, email: Email, ctx: WorkflowContext[AnalysisRequest]) -> None:
        await ctx.send_message(self._to_request(email))

    @staticmethod
    def normalize(payload: dict[str, Any], source: str = "json") -> Email:
        """Map an external payload onto the canonical schema."""
        if source == "graph":
            return IngestionExecutor.from_graph_message(payload)
        return Email.model_validate(payload)

    @staticmethod
    def from_graph_message(message: dict[str, Any]) -> Email:
        """Microsoft Graph `message` resource -> normalized Email (§9).

        Implemented against the documented Graph shape so the migration path is
        concrete rather than aspirational. Not exercised in the local POC.
        """
        sender = (message.get("from") or {}).get("emailAddress", {})
        reply_to_list = message.get("replyTo") or []
        body = message.get("body") or {}
        content_type = (body.get("contentType") or "text").lower()
        headers = {h.get("name", ""): h.get("value", "") for h in message.get("internetMessageHeaders", []) or []}
        return Email(
            message_id=message.get("internetMessageId") or message.get("id", ""),
            sender={"display_name": sender.get("name", ""), "address": (sender.get("address") or "").lower()},
            reply_to=(
                {
                    "display_name": reply_to_list[0]["emailAddress"].get("name", ""),
                    "address": reply_to_list[0]["emailAddress"].get("address", "").lower(),
                }
                if reply_to_list
                else None
            ),
            recipients=[
                {"display_name": r["emailAddress"].get("name", ""), "address": r["emailAddress"].get("address", "").lower()}
                for r in (message.get("toRecipients") or [])
                if r.get("emailAddress")
            ],
            subject=message.get("subject", ""),
            body_text=body.get("content", "") if content_type == "text" else "",
            body_html=body.get("content", "") if content_type == "html" else "",
            headers=headers,
            attachments=[
                {
                    "filename": a.get("name", ""),
                    "content_type": a.get("contentType", "application/octet-stream"),
                    "size_bytes": a.get("size", 0),
                }
                for a in (message.get("attachments") or [])
            ],
        )

    @staticmethod
    def _to_request(email: Email) -> AnalysisRequest:
        correlation_id = new_correlation_id()
        set_correlation_id(correlation_id)
        trace = get_trace(correlation_id, email.message_id)
        trace.record("EMAIL_RECEIVED", sender=email.sender.address, subject=email.subject[:120])
        if not email.urls:
            from email_security.tools.url_tools import extract_urls

            email.urls = extract_urls(email.body_text, email.body_html)
        for attachment in email.attachments:
            attachment.ensure_hash()
        trace.record(
            "EMAIL_NORMALIZED",
            urls=len(email.urls),
            attachments=len(email.attachments),
            recipients=len(email.recipients),
        )
        return AnalysisRequest(email=email, correlation_id=correlation_id, started_at=time.perf_counter())


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


class OrchestratorExecutor(Executor):
    """Decides which specialists run, publishes shared State, and fans out.

    It is intentionally *not* an LLM agent by default: dispatch in a security
    pipeline should be reproducible and un-influenceable by the message.
    """

    def __init__(
        self,
        available_agents: list[str],
        *,
        executor_id: str = "orchestrator",
        settings: Settings | None = None,
        provider: Any = None,
    ) -> None:
        super().__init__(id=executor_id)
        self._settings = settings or get_settings()
        self._available = available_agents
        self._router: Any
        if self._settings.agents.enable_llm_router and provider is not None:
            self._router = LLMRouter(available_agents, provider)
        else:
            self._router = DeterministicRouter(available_agents)

    @handler
    async def dispatch(self, request: AnalysisRequest, ctx: WorkflowContext[AnalysisRequest]) -> None:
        with request.trace.span("ORCHESTRATOR_STARTED", router=self._router.mode):
            decision = self._router.route(request.email)
            if hasattr(decision, "__await__"):  # LLMRouter.route is async
                decision = await decision  # type: ignore[misc]
            request.selected_agents = decision.agents
            request.routing_rationale = decision.rationale

        # Shared workflow State: the fan-in aggregator receives only
        # list[AgentVerdict], so the request context travels here instead of
        # being duplicated onto every edge.
        ctx.set_state(STATE_REQUEST_KEY, request)
        request.trace.record(
            "AGENTS_DISPATCHED",
            agents=",".join(decision.agents),
            mode=decision.mode,
            rationale=decision.rationale,
        )
        await ctx.send_message(request)


# --------------------------------------------------------------------------- #
# Risk aggregation
# --------------------------------------------------------------------------- #


class RiskAggregatorExecutor(Executor):
    """Fan-in target. Merges N `AgentVerdict`s into one `AggregatedRisk`.

    It performs no model inference and applies no policy. Its only jobs are:
      * normalise per-agent scores into a stable score dictionary
      * pick the dominant threat class
      * compute a risk score that reflects corroboration between agents
      * report analysis *coverage*, which is what makes fail-safe possible
    """

    def __init__(self, expected_agents: list[str], executor_id: str = "risk_aggregator") -> None:
        super().__init__(id=executor_id)
        self._expected = expected_agents

    @handler
    async def aggregate(self, verdicts: list[AgentVerdict], ctx: WorkflowContext[RiskBundle]) -> None:
        request: AnalysisRequest | None = ctx.get_state(STATE_REQUEST_KEY)
        if request is None:  # pragma: no cover - only if the graph is rewired wrongly
            raise RuntimeError("Aggregator ran without an AnalysisRequest in workflow state")

        with request.trace.span("AGENT_RESULTS_COLLECTED", verdicts=len(verdicts)):
            risk = self.build_risk(verdicts, request)
        request.trace.record(
            "RISK_AGGREGATED",
            risk_score=risk.risk_score,
            dominant=str(risk.dominant_class),
            coverage=round(risk.coverage, 3),
            degraded=",".join(risk.degraded_agents),
            **{k: round(v, 3) for k, v in risk.scores.items()},
        )
        await ctx.send_message(RiskBundle(risk=risk, request=request))

    def build_risk(self, verdicts: list[AgentVerdict], request: AnalysisRequest) -> AggregatedRisk:
        expected = request.selected_agents or self._expected
        scores: dict[str, float] = {}
        reasons: list[str] = []
        degraded: list[str] = []
        returned: set[str] = set()

        for verdict in verdicts:
            returned.add(verdict.agent_name)
            key = AGENT_SCORE_KEYS.get(verdict.agent_name, f"{verdict.agent_name}_score")
            scores[key] = max(scores.get(key, 0.0), verdict.score)
            if verdict.degraded:
                degraded.append(verdict.agent_name)

        missing = [name for name in expected if name not in returned]
        for name in missing:
            # An agent that never reported is not a vote of confidence. It gets
            # a null score and reduces coverage, which the policy engine sees.
            degraded.append(name)
            reasons.append(f"Agent {name} produced no verdict (timeout, crash, or dropped message)")

        coverage = (len(returned) / len(expected)) if expected else 1.0

        # Reasons: the strongest evidence from the highest-scoring agents.
        for verdict in sorted(verdicts, key=lambda v: v.score, reverse=True)[:3]:
            if verdict.score < 0.3:
                continue
            for line in verdict.evidence[:3]:
                reasons.append(f"{verdict.agent_name}: {line}")
        for verdict in verdicts:
            if verdict.degraded and verdict.errors:
                reasons.append(f"{verdict.agent_name} ran degraded: {verdict.errors[0]}")

        dominant = self.derive_class(verdicts, scores)
        risk_score = self.compute_risk_score(scores)
        confidence = self.compute_confidence(verdicts, coverage)

        return AggregatedRisk(
            message_id=request.email.message_id,
            correlation_id=request.correlation_id,
            scores={k: round(v, 4) for k, v in scores.items()},
            dominant_class=dominant,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            reasons=reasons[:12],
            agent_results=verdicts,
            degraded_agents=sorted(set(degraded)),
            coverage=coverage,
        )

    @staticmethod
    def derive_class(verdicts: list[AgentVerdict], scores: dict[str, float]) -> ThreatClass:
        """Pick the threat family, breaking ties by consequence severity.

        Special case: a message whose only strong signal is *identity* deception
        — no credential ask, no payload, no financial request — is impersonation
        rather than phishing or BEC. That distinction changes the response
        (review rather than quarantine), so it is made explicitly.
        """
        candidates: list[tuple[ThreatClass, float]] = [
            (ThreatClass.MALWARE, scores.get("malware_score", 0.0)),
            (ThreatClass.PHISHING, max(scores.get("phishing_score", 0.0), scores.get("url_score", 0.0))),
            (ThreatClass.BEC, scores.get("bec_score", 0.0)),
            (ThreatClass.SPAM, scores.get("spam_score", 0.0)),
        ]
        best_score = max((s for _, s in candidates), default=0.0)
        if best_score < 0.35:
            return ThreatClass.CLEAN

        # Confirmed payload delivery outranks the pretext used to deliver it.
        # A malicious attachment wrapped in a brand-impersonation lure is
        # malware, not phishing: it is the payload that determines containment,
        # forensics and the hunt query an analyst runs next.
        if scores.get("malware_score", 0.0) >= CONFIRMED_PAYLOAD_SCORE:
            return ThreatClass.MALWARE

        leaders = [cls for cls, score in candidates if score >= best_score - 0.05]
        dominant = min(leaders, key=lambda c: CLASS_PRIORITY.index(c))

        if dominant in {ThreatClass.PHISHING, ThreatClass.BEC}:
            indicator_ids = {i.id for v in verdicts for i in v.indicators}
            identity_markers = {
                "brand_impersonation_display_name", "sender_lookalike_domain", "sender_punycode",
                "executive_impersonation_freemail", "executive_impersonation_external",
                "named_executive_from_external_domain", "lookalike_sender_domain",
                "vendor_lookalike_domain", "department_impersonation", "internal_domain_spoof",
                # Impersonation of the tenant's OWN domain — the highest-signal
                # identity marker there is, and the one most easily forgotten
                # because it comes from tenant context rather than a brand list.
                "org_domain_lookalike",
            }
            action_markers = {
                i for i in indicator_ids
                if i.startswith(("credential_intent:", "financial:", "malicious_link", "lookalike_link",
                                 "credential_harvest_kit", "inline_credential_form", "url:"))
            }
            if indicator_ids & identity_markers and not action_markers:
                return ThreatClass.IMPERSONATION
        return dominant

    @staticmethod
    def compute_risk_score(scores: dict[str, float]) -> float:
        """Highest single threat, lifted slightly when other agents corroborate.

        Deliberately not a mean: a 0.95 malware score must not be diluted by four
        agents correctly reporting 0.0 for their own specialities.
        """
        if not scores:
            return 0.0
        ordered = sorted(scores.values(), reverse=True)
        top = ordered[0]
        corroboration = sum(s for s in ordered[1:] if s >= 0.5)
        return min(1.0, top + 0.05 * corroboration)

    @staticmethod
    def compute_confidence(verdicts: list[AgentVerdict], coverage: float) -> float:
        """Confidence of the agents that actually drove the outcome, scaled by coverage."""
        if not verdicts:
            return 0.0
        contributing = [v for v in verdicts if v.score >= 0.35] or verdicts
        weight_total = sum(max(v.score, 0.05) for v in contributing)
        weighted = sum(v.confidence * max(v.score, 0.05) for v in contributing) / weight_total
        return max(0.0, min(1.0, weighted * (0.6 + 0.4 * coverage)))


# --------------------------------------------------------------------------- #
# Policy + terminal executors
# --------------------------------------------------------------------------- #


class PolicyExecutor(Executor):
    """Applies the deterministic policy engine. No model involvement."""

    def __init__(self, engine: PolicyEngine | None = None, executor_id: str = "policy_engine") -> None:
        super().__init__(id=executor_id)
        self._engine = engine or PolicyEngine()

    @handler
    async def enforce(self, bundle: RiskBundle, ctx: WorkflowContext[DecisionBundle]) -> None:
        request = bundle.request
        with request.trace.span("POLICY_ENGINE", rules=len(self._engine.rules)):
            decision = self._engine.decide(bundle.risk)
        decision.total_latency_ms = round((time.perf_counter() - request.started_at) * 1000, 2)
        request.trace.record(
            "POLICY_EVALUATED",
            action=str(decision.recommended_action),
            classification=str(decision.final_classification),
            rules=",".join(decision.policy_rules_fired),
            fail_safe=decision.fail_safe_applied,
        )
        await ctx.send_message(DecisionBundle(decision=decision, request=request))


class DeliveryExecutor(Executor):
    """Terminal node for messages that need no human. Yields the final Decision."""

    def __init__(self, executor_id: str = "final_decision") -> None:
        super().__init__(id=executor_id)

    @handler
    async def finalize(self, bundle: DecisionBundle, ctx: WorkflowContext[None, Decision]) -> None:
        decision = bundle.decision
        request = bundle.request
        request.trace.record(
            "FINAL_DECISION",
            action=str(decision.recommended_action),
            classification=str(decision.final_classification),
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            latency_ms=decision.total_latency_ms,
        )
        decision.trace = request.trace.as_list()
        release_trace(decision.correlation_id)
        await ctx.yield_output(decision)


class HumanReviewExecutor(Executor):
    """Analyst escalation path (§17).

    Two modes:
      queue        — default. The decision is emitted immediately, flagged for
                     review, and the message is held. Nothing blocks; this is how
                     a real SOC queue behaves.
      request_info — the workflow *pauses* and emits a RequestInfoEvent. The
                     caller supplies a `HumanReviewResponse` to resume. This is
                     Agent Framework's built-in human-in-the-loop primitive and
                     is what an interactive analyst console would use.
    """

    def __init__(self, mode: str = "queue", executor_id: str = "human_review") -> None:
        super().__init__(id=executor_id)
        if mode not in {"queue", "request_info"}:
            raise ValueError(f"unknown human review mode: {mode}")
        self.mode = mode
        self._pending: dict[str, DecisionBundle] = {}

    @handler
    async def escalate(self, bundle: DecisionBundle, ctx: WorkflowContext[None, Decision]) -> None:
        decision = bundle.decision
        request = bundle.request
        review = HumanReviewRequest(
            message_id=decision.message_id,
            correlation_id=decision.correlation_id,
            subject=request.email.subject,
            sender=request.email.sender.address,
            proposed_action=decision.recommended_action,
            risk_score=decision.risk_score,
            reasons=decision.reasons[:6],
        )
        request.trace.record(
            "HUMAN_REVIEW_QUEUED",
            proposed_action=str(decision.recommended_action),
            risk_score=decision.risk_score,
            mode=self.mode,
        )

        if self.mode == "request_info":
            self._pending[decision.correlation_id] = bundle
            await ctx.request_info(review, HumanReviewResponse, request_id=decision.correlation_id)
            return

        decision.requires_human_review = True
        request.trace.record("FINAL_DECISION", action=str(decision.recommended_action),
                             classification=str(decision.final_classification), held_for_review=True,
                             latency_ms=decision.total_latency_ms)
        decision.trace = request.trace.as_list()
        release_trace(decision.correlation_id)
        await ctx.yield_output(decision)

    # Explicit types: `from __future__ import annotations` turns the signature
    # into strings, which the response-handler validator does not resolve.
    @response_handler(request=HumanReviewRequest, response=HumanReviewResponse, workflow_output=Decision)
    async def adjudicated(
        self,
        original_request: HumanReviewRequest,
        response: HumanReviewResponse,
        ctx: WorkflowContext[None, Decision],
    ) -> None:
        """Resume after an analyst decides. The analyst overrides the policy."""
        bundle = self._pending.pop(original_request.correlation_id, None)
        if bundle is None:  # pragma: no cover
            raise RuntimeError(f"No pending review for {original_request.correlation_id}")
        decision = bundle.decision
        decision.recommended_action = response.decision
        decision.requires_human_review = False
        decision.reasons.append(f"[HUMAN] {response.analyst} chose {response.decision}: {response.rationale}")
        if response.decision is Action.DELIVER:
            decision.final_classification = ThreatClass.CLEAN
        bundle.request.trace.record(
            "HUMAN_REVIEW_COMPLETED", analyst=response.analyst, action=str(response.decision)
        )
        bundle.request.trace.record("FINAL_DECISION", action=str(response.decision), adjudicated=True)
        decision.trace = bundle.request.trace.as_list()
        release_trace(decision.correlation_id)
        await ctx.yield_output(decision)
