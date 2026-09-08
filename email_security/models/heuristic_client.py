"""Offline stand-in chat client (§5 fallback path).

WHAT THIS IS NOT: it is not a language model, and it does not perform any
semantic reasoning. It is a deterministic component that satisfies the
`BaseChatClient` contract so the *whole* multi-agent architecture — agents,
workflow, structured outputs, fan-in, policy — can be executed and evaluated on
a machine with no model installed and no network access.

It works by reading the machine-readable `<EVIDENCE>` block that every agent
embeds in its prompt and restating that evidence as a structured
`LLMAssessment`. Because it only echoes deterministic findings, a run under this
client is effectively a *rules-only* run: any reported accuracy belongs to the
tool layer, not to a model. Point `LLM_PROVIDER=ollama` at a real model to get
genuine semantic coverage of novel, unseen lures.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Awaitable, Mapping, Sequence
from typing import Any

from agent_framework import (
    BaseChatClient,
    ChatResponse,
    ChatResponseUpdate,
    FunctionInvocationLayer,
    Message,
    ResponseStream,
)

EVIDENCE_RE = re.compile(r"<EVIDENCE>\s*(\{.*?\})\s*</EVIDENCE>", re.DOTALL)


class HeuristicChatClient(FunctionInvocationLayer, BaseChatClient):
    """Deterministic `BaseChatClient` used when no local model is available.

    `FunctionInvocationLayer` is mixed in so the client satisfies the same
    protocol as a real one (and Agent construction stays quiet). The stub simply
    never emits a tool call, so the layer is a no-op.
    """

    OTEL_PROVIDER_NAME: str = "heuristic-offline"

    def __init__(self, model_id: str = "heuristic-offline", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.model_id = model_id

    @property
    def service_url(self) -> str:  # pragma: no cover - required by base class
        return "local://heuristic"

    def _inner_get_response(
        self,
        *,
        messages: Sequence[Message],
        stream: bool = False,
        options: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Awaitable[ChatResponse] | ResponseStream[ChatResponseUpdate, ChatResponse]:
        options = options or {}
        payload = self._assess(messages)
        text = json.dumps(payload)

        if stream:
            async def _stream() -> AsyncIterator[ChatResponseUpdate]:
                yield ChatResponseUpdate(contents=[text], role="assistant")

            return self._build_response_stream(_stream(), response_format=options.get("response_format"))

        async def _get_response() -> ChatResponse:
            return ChatResponse(
                messages=[Message(role="assistant", contents=[text])],
                model=self.model_id,
                response_format=options.get("response_format"),
            )

        return _get_response()

    # ------------------------------------------------------------------ #

    @staticmethod
    def _assess(messages: Sequence[Message]) -> dict[str, Any]:
        """Restate the prompt's evidence block as a structured assessment."""
        blob = "\n".join(m.text or "" for m in messages)
        match = EVIDENCE_RE.search(blob)
        if not match:
            return {
                "score": 0.0,
                "confidence": 0.2,
                "verdict": "CLEAN",
                "reasons": ["No structured evidence supplied to the offline reasoning stub."],
                "observed_techniques": [],
            }
        try:
            evidence = json.loads(match.group(1))
        except json.JSONDecodeError:
            return {"score": 0.0, "confidence": 0.2, "verdict": "CLEAN", "reasons": ["Malformed evidence block."], "observed_techniques": []}

        indicators = evidence.get("indicators", []) or []
        baseline = float(evidence.get("deterministic_score", 0.0) or 0.0)
        techniques = [str(i.get("id", "")) for i in indicators if isinstance(i, dict)][:12]
        reasons = [str(i.get("description", "")) for i in indicators if isinstance(i, dict)][:8]
        threat_class = str(evidence.get("threat_class", "SUSPICIOUS"))

        verdict = threat_class if baseline >= 0.5 else "SUSPICIOUS" if baseline >= 0.3 else "CLEAN"
        return {
            # Echo the deterministic score; the offline stub adds no new evidence.
            "score": round(min(1.0, baseline), 3),
            # Deliberately capped: an evidence echo is not model confidence.
            "confidence": 0.45,
            "verdict": verdict,
            "reasons": reasons or ["No deterministic indicators fired."],
            "observed_techniques": techniques,
        }
