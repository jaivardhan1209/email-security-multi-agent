"""Agent routing (§2).

Two routing modes, and the choice between them is the most important
architectural decision in this system:

DETERMINISTIC ROUTING (default, and correct for security)
    A static table maps observable message properties to the agents that must
    run. It is reproducible, auditable, has bounded latency, and — decisively —
    it cannot be manipulated by the message being analysed. An attacker who can
    influence which detectors run has already defeated the system, so routing
    must never depend on attacker-controlled text.

LLM ROUTING (opt-in, ENABLE_LLM_ROUTER=true)
    A model proposes which agents to run. Useful when the agent catalogue is
    large and heterogeneous and running everything is genuinely too expensive.
    Here it is deliberately constrained: the model may only ADD agents to the
    mandatory set, never remove one. That keeps the safety property while
    letting the model contribute.

For a five-agent POC, running everything concurrently costs one LLM round-trip
of wall-clock time, so deterministic full fan-out is both safer and cheaper.
Selective routing is an optimisation to reach for at tenant scale, not before.
"""

from __future__ import annotations

from dataclasses import dataclass

from email_security.models.schemas import Email
from email_security.observability import get_logger

logger = get_logger("router")

#: Agents that run on every message, regardless of content. These cover the
#: threat classes whose false negatives are most expensive.
MANDATORY_AGENTS: tuple[str, ...] = ("phishing_agent", "malware_agent", "bec_agent")

#: Agents added when a cheap structural precondition holds.
CONDITIONAL_AGENTS: tuple[str, ...] = ("spam_agent", "url_agent")


@dataclass(slots=True)
class RoutingDecision:
    agents: list[str]
    rationale: str
    mode: str


class DeterministicRouter:
    """Static, auditable routing. The default and the recommended mode."""

    mode = "deterministic"

    def __init__(self, available: list[str]) -> None:
        self.available = list(available)

    def route(self, email: Email) -> RoutingDecision:
        selected = [name for name in MANDATORY_AGENTS if name in self.available]
        reasons = ["mandatory: phishing, malware, BEC always run"]

        has_links = bool(email.urls) or "http" in (email.body_html or email.body_text or "").lower()
        if "url_agent" in self.available:
            if has_links:
                selected.append("url_agent")
                reasons.append("url_agent: message contains links")
            else:
                # Still run it: URL extraction is cheap and a missed link is a
                # missed detection. Kept explicit so the trade-off is visible.
                selected.append("url_agent")
                reasons.append("url_agent: run unconditionally (extraction is cheap, misses are expensive)")
        if "spam_agent" in self.available:
            selected.append("spam_agent")
            reasons.append("spam_agent: run unconditionally (classifies unwanted bulk mail)")

        ordered = [name for name in self.available if name in set(selected)]
        return RoutingDecision(agents=ordered, rationale="; ".join(reasons), mode=self.mode)


class LLMRouter:
    """Model-proposed routing, floored by the mandatory set.

    NOTE the safety property: `route` unions the model's answer with
    MANDATORY_AGENTS. The model can only widen coverage, never narrow it.
    """

    mode = "llm"

    def __init__(self, available: list[str], provider) -> None:  # noqa: ANN001 - LLMProvider, avoids import cycle
        self.available = list(available)
        self._provider = provider
        self._fallback = DeterministicRouter(available)

    async def route(self, email: Email) -> RoutingDecision:
        from email_security.models.schemas import LLMAssessment  # local import: cycle avoidance

        try:
            agent = self._provider.create_agent(
                name="orchestrator_router",
                instructions=(
                    "You are a triage router in an email security system. Given a message summary, "
                    "list which specialist detectors should examine it. Available: "
                    f"{', '.join(self.available)}. Reply with the agent names in `observed_techniques`. "
                    "Never omit a detector you are unsure about — over-inclusion is free, a miss is not."
                ),
            )
            summary = (
                f"Subject: {email.subject}\nFrom: {email.sender}\n"
                f"Attachments: {[a.filename for a in email.attachments]}\nURLs: {email.urls[:8]}\n"
                f"Body preview: {email.body[:600]}"
            )
            response = await agent.run(summary, options={"response_format": LLMAssessment})
            proposed = {t.strip() for t in (getattr(response.value, "observed_techniques", None) or [])}
        except Exception as exc:  # noqa: BLE001 - routing must never block analysis
            logger.warning("LLM router failed (%s); using deterministic routing", exc)
            return self._fallback.route(email)

        selected = set(MANDATORY_AGENTS) | {name for name in proposed if name in self.available}
        ordered = [name for name in self.available if name in selected]
        return RoutingDecision(
            agents=ordered,
            rationale=f"LLM proposed {sorted(proposed)}; unioned with mandatory set",
            mode=self.mode,
        )
