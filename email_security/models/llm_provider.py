"""Pluggable LLM layer (§5).

    LLMProvider
      ├── OfflineProvider      -> HeuristicChatClient (no model, always available)
      ├── OllamaProvider       -> agent_framework.ollama.OllamaChatClient
      ├── HuggingFaceProvider  -> local transformers pipeline
      └── FoundryProvider      -> Azure AI Foundry (production target)

Model-specific code lives *only* here. Agents receive an `Agent` object and
never learn which runtime produced it, which is what makes the local-POC ->
Foundry migration a configuration change rather than a rewrite.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Mapping, Sequence
from typing import Any

import httpx
from agent_framework import Agent, BaseChatClient, ChatResponse, ChatResponseUpdate, Message, ResponseStream

from email_security.config.settings import LLMSettings, Settings, get_settings
from email_security.models.heuristic_client import HeuristicChatClient
from email_security.observability import get_logger

logger = get_logger("llm")


class LLMProviderError(RuntimeError):
    """Raised when a provider cannot be constructed. Agents degrade, not crash."""


class LLMProvider(ABC):
    """Abstract model runtime. One method matters: `create_agent`."""

    name: str = "abstract"

    def __init__(self, settings: LLMSettings) -> None:
        self.settings = settings

    @abstractmethod
    def create_chat_client(self) -> BaseChatClient:
        """Return a configured Agent Framework chat client."""

    @abstractmethod
    def health_check(self) -> tuple[bool, str]:
        """Cheap liveness probe. Never raises."""

    @property
    def model_name(self) -> str:
        return self.settings.model

    #: Whether this runtime can execute model-requested function calls.
    supports_tools: bool = True

    def default_options(self) -> dict[str, Any]:
        return {
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
        }

    def create_agent(
        self,
        *,
        name: str,
        instructions: str,
        tools: Sequence[Any] | None = None,
        description: str = "",
    ) -> Agent:
        """Build an Agent Framework `Agent` bound to this runtime.

        The agent is a *reasoning* component only: its tools are the same pure
        functions the executor already called deterministically, exposed so a
        tool-capable model can request extra lookups it thinks are missing.
        """
        client = self.create_chat_client()
        return Agent(
            client=client,
            instructions=instructions,
            name=name,
            description=description or name,
            tools=list(tools) if (tools and self.supports_tools) else None,
        )

    def describe(self) -> dict[str, Any]:
        ok, detail = self.health_check()
        return {"provider": self.name, "model": self.model_name, "available": ok, "detail": detail}


# --------------------------------------------------------------------------- #
# Offline (default) — lets the architecture run with zero external dependencies
# --------------------------------------------------------------------------- #


class OfflineProvider(LLMProvider):
    """No model. Deterministic evidence-echo stub. See `heuristic_client`."""

    name = "offline"
    supports_tools = False

    def create_chat_client(self) -> BaseChatClient:
        return HeuristicChatClient(model_id="heuristic-offline")

    def health_check(self) -> tuple[bool, str]:
        return True, "offline heuristic stub — no language model in use"

    @property
    def model_name(self) -> str:
        return "heuristic-offline"


# --------------------------------------------------------------------------- #
# Ollama — the recommended POC path
# --------------------------------------------------------------------------- #


class OllamaProvider(LLMProvider):
    """Local open-source model served by Ollama.

    Recommended models, in order of preference for this workload:
      * qwen2.5:7b-instruct   — best instruction-following/JSON adherence per GB
      * llama3.1:8b-instruct  — strong general reasoning, needs ~6 GB VRAM
      * mistral:7b-instruct   — fast, slightly weaker at structured output
      * qwen2.5:3b-instruct   — CPU-only / <8 GB RAM machines
    """

    name = "ollama"

    def create_chat_client(self) -> BaseChatClient:
        try:
            from agent_framework.ollama import OllamaChatClient
        except (ImportError, ModuleNotFoundError) as exc:  # pragma: no cover
            raise LLMProviderError(
                "agent-framework-ollama is not installed. Run: pip install agent-framework-ollama"
            ) from exc
        return OllamaChatClient(host=self.settings.host, model=self.settings.model)

    def health_check(self) -> tuple[bool, str]:
        try:
            response = httpx.get(f"{self.settings.host.rstrip('/')}/api/tags", timeout=3.0)
            response.raise_for_status()
            tags = [m.get("model", "") for m in response.json().get("models", [])]
        except Exception as exc:  # noqa: BLE001 - probe must never raise
            return False, f"Ollama unreachable at {self.settings.host}: {type(exc).__name__}"
        if not tags:
            return False, "Ollama is running but no models are pulled"
        wanted = self.settings.model
        if wanted not in tags and not any(t.split(":")[0] == wanted.split(":")[0] for t in tags):
            return False, f"model '{wanted}' not pulled (available: {', '.join(tags[:5])})"
        return True, f"ollama ok, {len(tags)} model(s) available"


# --------------------------------------------------------------------------- #
# Hugging Face transformers — no daemon required
# --------------------------------------------------------------------------- #


class TransformersChatClient(BaseChatClient):
    """Minimal `BaseChatClient` over a local `transformers` text-generation pipeline."""

    OTEL_PROVIDER_NAME: str = "huggingface"

    def __init__(self, model_id: str, max_tokens: int = 700, temperature: float = 0.0, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.model_id = model_id
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._pipe: Any = None

    @property
    def service_url(self) -> str:  # pragma: no cover
        return f"local://transformers/{self.model_id}"

    def _ensure_pipeline(self) -> Any:
        if self._pipe is None:
            from transformers import pipeline  # imported lazily: heavy dependency

            self._pipe = pipeline("text-generation", model=self.model_id, device_map="auto")
        return self._pipe

    def _inner_get_response(
        self,
        *,
        messages: Sequence[Message],
        stream: bool = False,
        options: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Awaitable[ChatResponse] | ResponseStream[ChatResponseUpdate, ChatResponse]:
        import asyncio

        options = options or {}
        response_format = options.get("response_format")

        def _generate() -> str:
            pipe = self._ensure_pipeline()
            chat = [{"role": m.role.value if hasattr(m.role, "value") else str(m.role), "content": m.text or ""} for m in messages]
            if response_format is not None and hasattr(response_format, "model_json_schema"):
                chat.append({
                    "role": "user",
                    "content": "Reply with a single JSON object matching this schema and nothing else:\n"
                    + json.dumps(response_format.model_json_schema()),
                })
            out = pipe(
                chat,
                max_new_tokens=self.max_tokens,
                do_sample=self.temperature > 0,
                temperature=max(self.temperature, 0.01),
                return_full_text=False,
            )
            generated = out[0]["generated_text"]
            return generated if isinstance(generated, str) else generated[-1]["content"]

        async def _get_response() -> ChatResponse:
            raw = await asyncio.to_thread(_generate)
            text = _extract_json(raw) if response_format is not None else raw
            return ChatResponse(
                messages=[Message(role="assistant", contents=[text])],
                model=self.model_id,
                response_format=response_format,
            )

        if stream:
            async def _stream() -> AsyncIterator[ChatResponseUpdate]:
                text = await asyncio.to_thread(_generate)
                yield ChatResponseUpdate(contents=[text], role="assistant")

            return self._build_response_stream(_stream(), response_format=response_format)
        return _get_response()


def _extract_json(text: str) -> str:
    """Pull the first balanced JSON object out of a model's prose (§16)."""
    start = text.find("{")
    if start == -1:
        return "{}"
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return re.sub(r"\s+", " ", text[start:]) or "{}"


class HuggingFaceProvider(LLMProvider):
    """Local transformers inference. Heavier to start, no daemon required."""

    name = "huggingface"

    def create_chat_client(self) -> BaseChatClient:
        return TransformersChatClient(
            model_id=self.settings.hf_model,
            max_tokens=self.settings.max_tokens,
            temperature=self.settings.temperature,
        )

    def health_check(self) -> tuple[bool, str]:
        try:
            import transformers  # noqa: F401
        except ImportError:
            return False, "transformers not installed (pip install '.[huggingface]')"
        return True, f"transformers available for {self.settings.hf_model}"

    @property
    def model_name(self) -> str:
        return self.settings.hf_model


# --------------------------------------------------------------------------- #
# Azure AI Foundry — production target (§18)
# --------------------------------------------------------------------------- #


class FoundryProvider(LLMProvider):
    """Azure AI Foundry-hosted model.

    Intentionally the thinnest class in this file: it exists to prove the seam.
    Migration is `LLM_PROVIDER=foundry` plus credentials — no agent, workflow,
    tool or policy code changes.
    """

    name = "foundry"

    def create_chat_client(self) -> BaseChatClient:
        if not self.settings.foundry_endpoint:
            raise LLMProviderError("AZURE_AI_PROJECT_ENDPOINT is not configured")
        try:
            from agent_framework.azure import AzureAIAgentClient  # type: ignore[import-not-found]
        except (ImportError, ModuleNotFoundError) as exc:
            raise LLMProviderError(
                "Foundry support requires: pip install agent-framework-azure-ai azure-identity"
            ) from exc
        from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]

        return AzureAIAgentClient(
            project_endpoint=self.settings.foundry_endpoint,
            model_deployment_name=self.settings.foundry_deployment,
            async_credential=DefaultAzureCredential(),
        )

    def health_check(self) -> tuple[bool, str]:
        if not self.settings.foundry_endpoint:
            return False, "AZURE_AI_PROJECT_ENDPOINT not set"
        try:
            import agent_framework.azure  # noqa: F401
        except (ImportError, ModuleNotFoundError):
            return False, "agent-framework-azure-ai not installed"
        return True, "foundry configured"

    @property
    def model_name(self) -> str:
        return self.settings.foundry_deployment or "foundry-deployment"


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "offline": OfflineProvider,
    "ollama": OllamaProvider,
    "huggingface": HuggingFaceProvider,
    "foundry": FoundryProvider,
}


def get_llm_provider(settings: Settings | None = None, *, fallback_to_offline: bool = True) -> LLMProvider:
    """Resolve the configured provider, degrading to offline if it is unhealthy.

    Fail-safe (§16): an unavailable model must never abort analysis. It
    downgrades the *reasoning* layer while the deterministic layer keeps running,
    and every affected verdict is flagged `degraded=True`.
    """
    settings = settings or get_settings()
    requested = settings.llm.provider
    provider_cls = _PROVIDERS.get(requested)
    if provider_cls is None:
        logger.warning("Unknown LLM_PROVIDER '%s'; falling back to offline", requested)
        return OfflineProvider(settings.llm)

    provider = provider_cls(settings.llm)
    ok, detail = provider.health_check()
    if not ok and fallback_to_offline:
        logger.warning(
            "LLM provider '%s' unavailable (%s); degrading to offline heuristic reasoning",
            requested,
            detail,
            extra={"fields": {"provider": requested, "detail": detail}},
        )
        return OfflineProvider(settings.llm)
    return provider


def register_provider(name: str, cls: type[LLMProvider]) -> None:
    """Extension point for custom runtimes (vLLM, llama.cpp server, ONNX...)."""
    _PROVIDERS[name] = cls
