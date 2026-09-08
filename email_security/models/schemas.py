"""Canonical data contracts for the email-security multi-agent system.

Every message that crosses an agent boundary is one of these Pydantic models.
Nothing is passed between components as free-form natural language: the LLM is
used *inside* an agent to produce structured fields, never as the transport
between agents.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class ThreatClass(StrEnum):
    """Threat taxonomy. Mirrors the verdict families used by Defender for O365."""

    CLEAN = "CLEAN"
    SPAM = "SPAM"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    BEC = "BEC"
    IMPERSONATION = "IMPERSONATION"
    SUSPICIOUS = "SUSPICIOUS"


class Action(StrEnum):
    """Terminal actions the policy engine may take on a message."""

    DELIVER = "DELIVER"                      # -> Inbox
    JUNK = "JUNK"                            # -> Junk Email folder
    QUARANTINE = "QUARANTINE"                # -> Admin quarantine, not delivered
    HIGH_RISK_REVIEW = "HIGH_RISK_REVIEW"    # -> Human analyst queue
    BLOCK = "BLOCK"                          # -> Reject at transport


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthResult(StrEnum):
    """SPF / DKIM / DMARC evaluation outcome."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


# --------------------------------------------------------------------------- #
# Email model (§8 normalized input schema)
# --------------------------------------------------------------------------- #


class EmailAddress(BaseModel):
    """A parsed RFC 5322 address: display name plus the real mailbox."""

    model_config = ConfigDict(frozen=True)

    display_name: str = ""
    address: str = ""

    @property
    def domain(self) -> str:
        return self.address.rsplit("@", 1)[-1].lower() if "@" in self.address else ""

    @property
    def local_part(self) -> str:
        return self.address.rsplit("@", 1)[0].lower() if "@" in self.address else ""

    @classmethod
    def parse(cls, raw: str | dict[str, Any] | EmailAddress) -> EmailAddress:
        if isinstance(raw, EmailAddress):
            return raw
        if isinstance(raw, dict):
            return cls(**raw)
        raw = (raw or "").strip()
        match = re.match(r'^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$', raw)
        if match:
            return cls(display_name=match.group(1).strip(), address=match.group(2).strip().lower())
        return cls(display_name="", address=raw.lower())

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.display_name} <{self.address}>" if self.display_name else self.address


class Attachment(BaseModel):
    """Attachment *metadata*. Payload bytes are optional and never executed.

    `extra="allow"` lets a corpus fixture carry findings from an upstream static
    scanner (e.g. `static_indicators`) without widening the core contract.
    """

    model_config = ConfigDict(extra="allow")

    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: str | None = None
    # Optional raw bytes for static inspection only (magic bytes, macro strings).
    content: bytes | None = Field(default=None, repr=False, exclude=True)

    def ensure_hash(self) -> str:
        """Compute SHA256 lazily; falls back to a stable synthetic digest."""
        if self.sha256:
            return self.sha256
        seed = self.content if self.content is not None else f"{self.filename}:{self.size_bytes}".encode()
        self.sha256 = hashlib.sha256(seed).hexdigest()
        return self.sha256


class Email(BaseModel):
    """Normalized email. This is the only shape the workflow ever sees.

    A Microsoft Graph message, an .eml file or a JSON fixture all converge here,
    which is what lets the ingestion source be swapped without touching agents.
    """

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: EmailAddress
    reply_to: EmailAddress | None = None
    return_path: EmailAddress | None = None
    recipients: list[EmailAddress] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Non-content context that a real deployment gets from the tenant graph.
    org_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sender", "reply_to", "return_path", mode="before")
    @classmethod
    def _coerce_address(cls, v: Any) -> Any:
        return EmailAddress.parse(v) if isinstance(v, str) else v

    @field_validator("recipients", mode="before")
    @classmethod
    def _coerce_recipients(cls, v: Any) -> Any:
        if isinstance(v, list):
            return [EmailAddress.parse(item) if isinstance(item, str) else item for item in v]
        return v

    @property
    def body(self) -> str:
        """Best-effort plain text view used by the language-level agents."""
        if self.body_text:
            return self.body_text
        return re.sub(r"<[^>]+>", " ", self.body_html)

    def header(self, name: str, default: str = "") -> str:
        lowered = {k.lower(): v for k, v in self.headers.items()}
        return lowered.get(name.lower(), default)


class LabeledEmail(BaseModel):
    """A test-set email carrying its ground-truth label (evaluation only)."""

    email: Email
    label: ThreatClass
    expected_action: Action
    difficulty: str = "normal"  # normal | borderline | hard
    notes: str = ""


# --------------------------------------------------------------------------- #
# Tool + agent contracts (§11 structured agent output)
# --------------------------------------------------------------------------- #


class ToolCall(BaseModel):
    """Observability record of one deterministic tool invocation."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    error: str | None = None


class Indicator(BaseModel):
    """A single machine-checkable detection signal.

    Indicators are produced by *tools* (deterministic) or by the LLM (semantic).
    `weight` drives the deterministic score; `source` records provenance so an
    analyst can tell rule-based evidence from model-inferred evidence.
    """

    id: str
    description: str
    severity: Severity = Severity.MEDIUM
    weight: float = Field(default=0.2, ge=0.0, le=1.0)
    source: str = "tool"  # tool | llm | heuristic
    details: dict[str, Any] = Field(default_factory=dict)


class AgentVerdict(BaseModel):
    """Uniform output contract for every detection agent.

    Fan-in in the workflow is typed on this model, so adding a new detection
    agent requires no change to the aggregator or the policy engine.
    """

    agent_name: str
    classification: ThreatClass
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    recommended_action: Action = Action.DELIVER
    execution_time_ms: float = 0.0

    # --- provenance / observability -------------------------------------- #
    model: str | None = None
    llm_used: bool = False
    deterministic_score: float = 0.0
    llm_score: float | None = None
    tools_called: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    degraded: bool = False  # True when the agent ran without full capability

    @property
    def failed(self) -> bool:
        return self.degraded and self.score == 0.0 and bool(self.errors)


class LLMAssessment(BaseModel):
    """Structured output the LLM itself must return. No free text between agents.

    This model is handed to the chat client as the `response_format`, so a
    JSON-schema-constrained decode is used where the runtime supports it.
    """

    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Threat likelihood 0.0-1.0")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in the score")
    verdict: str = Field(default="CLEAN", description="One of CLEAN, SUSPICIOUS, or the agent's threat class")
    reasons: list[str] = Field(default_factory=list, description="Short factual justifications")
    observed_techniques: list[str] = Field(default_factory=list, description="Named social-engineering or attack techniques")


# --------------------------------------------------------------------------- #
# Aggregation / decision contracts (§4)
# --------------------------------------------------------------------------- #


class AggregatedRisk(BaseModel):
    """Output of the Risk Aggregator, input to the Policy Engine."""

    message_id: str
    correlation_id: str
    scores: dict[str, float] = Field(default_factory=dict)
    dominant_class: ThreatClass = ThreatClass.CLEAN
    risk_score: float = 0.0
    confidence: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    agent_results: list[AgentVerdict] = Field(default_factory=list)
    degraded_agents: list[str] = Field(default_factory=list)
    coverage: float = 1.0  # fraction of dispatched agents that returned usable verdicts


class Decision(BaseModel):
    """Final, policy-enforced verdict for one message."""

    message_id: str
    correlation_id: str
    final_classification: ThreatClass
    risk_score: float
    confidence: float
    recommended_action: Action
    reasons: list[str] = Field(default_factory=list)
    agent_results: list[AgentVerdict] = Field(default_factory=list)
    policy_rules_fired: list[str] = Field(default_factory=list)
    requires_human_review: bool = False
    fail_safe_applied: bool = False
    total_latency_ms: float = 0.0
    trace: list[dict[str, Any]] = Field(default_factory=list)

    def summary(self) -> str:  # pragma: no cover - display helper
        return (
            f"{self.final_classification} risk={self.risk_score:.2f} "
            f"conf={self.confidence:.2f} action={self.recommended_action}"
        )


class HumanReviewRequest(BaseModel):
    """Payload surfaced to a human analyst (§17)."""

    message_id: str
    correlation_id: str
    subject: str
    sender: str
    proposed_action: Action
    risk_score: float
    reasons: list[str] = Field(default_factory=list)


class HumanReviewResponse(BaseModel):
    """Analyst adjudication returned into the workflow."""

    decision: Action = Action.QUARANTINE
    analyst: str = "unassigned"
    rationale: str = ""
