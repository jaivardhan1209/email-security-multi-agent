"""Environment-driven configuration. No secrets are hardcoded anywhere.

NOTE on `default_factory`: every env-derived default is wrapped in a factory
rather than evaluated inline. A bare `os.getenv(...)` default is evaluated once,
when the class is created, so `get_settings(refresh=True)` would silently return
the values that were present at import time.
"""

from __future__ import annotations

import os
from dataclasses import Field, dataclass, field
from typing import Literal

from dotenv import load_dotenv

load_dotenv(override=False)

ProviderName = Literal["ollama", "huggingface", "offline", "foundry"]


def _s(name: str, default: str) -> Field[str]:
    """String setting read at construction time."""
    return field(default_factory=lambda: os.getenv(name, default))


def _f(name: str, default: float) -> Field[float]:
    """Float setting; a malformed value falls back rather than crashing startup."""

    def read() -> float:
        try:
            return float(os.getenv(name, default))
        except (TypeError, ValueError):
            return default

    return field(default_factory=read)


def _i(name: str, default: int) -> Field[int]:
    def read() -> int:
        try:
            return int(os.getenv(name, default))
        except (TypeError, ValueError):
            return default

    return field(default_factory=read)


def _b(name: str, default: bool) -> Field[bool]:
    return field(default_factory=lambda: os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"})


@dataclass(slots=True)
class LLMSettings:
    """Which model backs the reasoning layer, and how hard we lean on it."""

    # `_s`/`_f`/`_i`/`_b` return dataclasses.Field objects, not values — the
    # supported way to express a computed default.
    provider: ProviderName = _s("LLM_PROVIDER", "offline")  # type: ignore[assignment]  # noqa: RUF009
    model: str = _s("LLM_MODEL", "qwen2.5:7b-instruct")
    host: str = _s("OLLAMA_HOST", "http://localhost:11434")
    temperature: float = _f("LLM_TEMPERATURE", 0.0)
    max_tokens: int = _i("LLM_MAX_TOKENS", 700)
    timeout_seconds: float = _f("LLM_TIMEOUT_SECONDS", 60.0)
    # Hugging Face fallback
    hf_model: str = _s("HF_MODEL", "Qwen/Qwen2.5-1.5B-Instruct")
    # Azure AI Foundry (future) — read from env only, never committed.
    foundry_endpoint: str = _s("AZURE_AI_PROJECT_ENDPOINT", "")
    foundry_deployment: str = _s("AZURE_AI_MODEL_DEPLOYMENT_NAME", "")


@dataclass(slots=True)
class AgentSettings:
    """Per-agent execution guardrails."""

    timeout_seconds: float = _f("AGENT_TIMEOUT_SECONDS", 45.0)
    retries: int = _i("AGENT_RETRIES", 1)
    # Weight of the LLM opinion when fusing with the deterministic score.
    llm_weight: float = _f("AGENT_LLM_WEIGHT", 0.4)
    # The deterministic layer can never be fully overruled downward by the LLM:
    # the fused score is floored at this fraction of the rule-based score.
    deterministic_floor_ratio: float = _f("AGENT_DETERMINISTIC_FLOOR", 0.75)
    enable_llm_router: bool = _b("ENABLE_LLM_ROUTER", False)


@dataclass(slots=True)
class PolicyThresholds:
    """§4 — deterministic security policy. Configurable, never model-decided."""

    malware_quarantine: float = _f("POLICY_MALWARE_QUARANTINE", 0.90)
    phishing_quarantine: float = _f("POLICY_PHISHING_QUARANTINE", 0.90)
    bec_review: float = _f("POLICY_BEC_REVIEW", 0.90)
    spam_junk: float = _f("POLICY_SPAM_JUNK", 0.85)
    impersonation_review: float = _f("POLICY_IMPERSONATION_REVIEW", 0.80)
    suspicious_floor: float = _f("POLICY_SUSPICIOUS_FLOOR", 0.50)
    # Combined-signal escalation: several medium signals are worse than one.
    composite_quarantine: float = _f("POLICY_COMPOSITE_QUARANTINE", 1.55)
    # Fail-safe: below this agent coverage, a message cannot be marked clean.
    min_coverage_for_clean: float = _f("POLICY_MIN_COVERAGE", 0.80)
    human_review_enabled: bool = _b("POLICY_HUMAN_REVIEW", True)


@dataclass(slots=True)
class ObservabilitySettings:
    log_level: str = _s("LOG_LEVEL", "INFO")
    log_format: str = _s("LOG_FORMAT", "json")  # json | text
    trace_file: str = _s("TRACE_FILE", "")
    otel_enabled: bool = _b("OTEL_ENABLED", False)


@dataclass(slots=True)
class Settings:
    llm: LLMSettings = field(default_factory=LLMSettings)
    agents: AgentSettings = field(default_factory=AgentSettings)
    policy: PolicyThresholds = field(default_factory=PolicyThresholds)
    observability: ObservabilitySettings = field(default_factory=ObservabilitySettings)


_settings: Settings | None = None


def get_settings(refresh: bool = False) -> Settings:
    """Process-wide settings singleton (injected, not imported, into agents).

    `refresh=True` re-reads the environment, which is what makes the settings
    testable and what lets a deployment reload configuration without a restart.
    """
    global _settings
    if _settings is None or refresh:
        _settings = Settings()
    return _settings
