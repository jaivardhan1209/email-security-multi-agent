"""Metric computation (§13).

Kept separate from the runner so the numbers can be unit-tested against known
confusion matrices rather than only against live pipeline output.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from email_security.models.schemas import Action, ThreatClass

#: Classes whose false negatives are security-critical: a miss here means a user
#: receives an attack in their inbox.
CRITICAL_CLASSES: tuple[ThreatClass, ...] = (ThreatClass.PHISHING, ThreatClass.MALWARE, ThreatClass.BEC)

#: Actions that actually stop a message reaching the user's inbox.
BLOCKING_ACTIONS: frozenset[Action] = frozenset({Action.QUARANTINE, Action.BLOCK, Action.HIGH_RISK_REVIEW, Action.JUNK})


@dataclass(slots=True)
class ClassMetrics:
    label: str
    support: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict[str, float | int | str]:
        return {
            "label": self.label, "support": self.support, "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4), "f1": round(self.f1, 4),
        }


@dataclass(slots=True)
class EvaluationSummary:
    total: int = 0
    correct_class: int = 0
    correct_action: int = 0
    per_class: dict[str, ClassMetrics] = field(default_factory=dict)
    # Threat-vs-clean binary view: this is what an administrator actually cares about.
    threat_tp: int = 0
    threat_fp: int = 0
    threat_tn: int = 0
    threat_fn: int = 0
    critical_false_negatives: list[dict[str, str]] = field(default_factory=list)
    false_positives: list[dict[str, str]] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)
    degraded_runs: int = 0

    # ---- derived -------------------------------------------------------- #

    @property
    def accuracy(self) -> float:
        return self.correct_class / self.total if self.total else 0.0

    @property
    def action_accuracy(self) -> float:
        return self.correct_action / self.total if self.total else 0.0

    @property
    def macro_f1(self) -> float:
        scored = [m for m in self.per_class.values() if m.support]
        return sum(m.f1 for m in scored) / len(scored) if scored else 0.0

    @property
    def threat_precision(self) -> float:
        return self.threat_tp / (self.threat_tp + self.threat_fp) if (self.threat_tp + self.threat_fp) else 0.0

    @property
    def threat_recall(self) -> float:
        return self.threat_tp / (self.threat_tp + self.threat_fn) if (self.threat_tp + self.threat_fn) else 0.0

    @property
    def threat_f1(self) -> float:
        p, r = self.threat_precision, self.threat_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.threat_fp + self.threat_tn
        return self.threat_fp / denom if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.threat_fn + self.threat_tp
        return self.threat_fn / denom if denom else 0.0

    def latency(self, percentile: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(len(ordered) - 1, round(percentile / 100 * (len(ordered) - 1)))
        return round(ordered[index], 2)


@dataclass(slots=True)
class AgentMetrics:
    """Per-agent detection quality (§13 'per-agent performance').

    An agent is judged only on its own speciality: the spam agent is scored
    against SPAM-labelled mail, not against malware. `threshold` is the score at
    which the agent is treated as asserting its class.
    """

    agent_name: str
    threat_class: ThreatClass
    threshold: float = 0.55
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    scores_on_positives: list[float] = field(default_factory=list)
    scores_on_negatives: list[float] = field(default_factory=list)
    durations_ms: list[float] = field(default_factory=list)
    degraded: int = 0
    errors: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def mean_score_positive(self) -> float:
        return sum(self.scores_on_positives) / len(self.scores_on_positives) if self.scores_on_positives else 0.0

    @property
    def mean_score_negative(self) -> float:
        return sum(self.scores_on_negatives) / len(self.scores_on_negatives) if self.scores_on_negatives else 0.0

    @property
    def separation(self) -> float:
        """Mean-score gap between in-class and out-of-class mail. Higher is better."""
        return self.mean_score_positive - self.mean_score_negative

    @property
    def mean_latency_ms(self) -> float:
        return sum(self.durations_ms) / len(self.durations_ms) if self.durations_ms else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "agent": self.agent_name, "class": str(self.threat_class), "threshold": self.threshold,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4), "f1": round(self.f1, 4),
            "mean_score_in_class": round(self.mean_score_positive, 4),
            "mean_score_out_of_class": round(self.mean_score_negative, 4),
            "separation": round(self.separation, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 2),
            "degraded_runs": self.degraded, "error_runs": self.errors,
        }


def build_class_metrics(labels: Iterable[ThreatClass]) -> dict[str, ClassMetrics]:
    return {str(label): ClassMetrics(label=str(label)) for label in labels}
