"""Specialist detection agents.

Each is an Agent Framework `Executor` that owns an LLM `Agent`, runs its own
deterministic tools first, and emits a typed `AgentVerdict`.
"""

from email_security.agents.base import DetectionAgent, Evidence
from email_security.agents.bec_agent import BecAgent
from email_security.agents.malware_agent import MalwareAgent
from email_security.agents.phishing_agent import PhishingAgent
from email_security.agents.spam_agent import SpamAgent
from email_security.agents.url_agent import UrlAgent

#: Registry consumed by the orchestrator. Adding a detection capability is a
#: one-line change here — the workflow, aggregator and policy adapt by contract.
AGENT_REGISTRY: dict[str, type[DetectionAgent]] = {
    "spam_agent": SpamAgent,
    "phishing_agent": PhishingAgent,
    "malware_agent": MalwareAgent,
    "bec_agent": BecAgent,
    "url_agent": UrlAgent,
}

__all__ = ["AGENT_REGISTRY", "BecAgent", "DetectionAgent", "Evidence", "MalwareAgent", "PhishingAgent", "SpamAgent", "UrlAgent"]
