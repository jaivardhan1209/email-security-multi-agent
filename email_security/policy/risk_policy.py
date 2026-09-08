"""Deterministic security policy engine (§4, §14).

THE CENTRAL RULE OF THIS SYSTEM: the LLM never decides what happens to a
message. Agents (LLM-assisted) produce *scores*; this module — pure Python,
no model, fully unit-testable, configurable via environment — converts scores
into actions.

Why: a language model's output is attacker-influenceable (the email body is
untrusted input) and non-reproducible. Mail flow decisions must be auditable
("rule R3 fired because phishing_score 0.94 >= 0.90"), reproducible, and
changeable by a security administrator without retraining or reprompting
anything. This is also how Defender for Office 365 is structured: detonation
and ML produce verdicts, but *policy* (anti-phishing policy, quarantine policy,
tenant allow/block) determines the action.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from email_security.config.settings import PolicyThresholds, Settings, get_settings
from email_security.models.schemas import Action, AggregatedRisk, Decision, ThreatClass

# Ordered severity: when several classes fire, the most damaging wins.
CLASS_PRIORITY: list[ThreatClass] = [
    ThreatClass.MALWARE,
    ThreatClass.PHISHING,
    ThreatClass.BEC,
    ThreatClass.IMPERSONATION,
    ThreatClass.SPAM,
    ThreatClass.SUSPICIOUS,
    ThreatClass.CLEAN,
]

# Action severity, used so a later rule can only ever escalate.
ACTION_SEVERITY: dict[Action, int] = {
    Action.DELIVER: 0,
    Action.JUNK: 1,
    Action.HIGH_RISK_REVIEW: 2,
    Action.QUARANTINE: 3,
    Action.BLOCK: 4,
}


@dataclass(slots=True)
class PolicyRule:
    """One auditable rule. `predicate` sees only scores — never message text."""

    id: str
    description: str
    predicate: Callable[[AggregatedRisk, PolicyThresholds], bool]
    action: Action
    classification: ThreatClass | None = None
    requires_human_review: bool = False


def _score(risk: AggregatedRisk, key: str) -> float:
    return float(risk.scores.get(key, 0.0))


def build_rules() -> list[PolicyRule]:
    """The rule set, evaluated in order. Every firing rule is recorded."""
    return [
        PolicyRule(
            id="R1_malware_quarantine",
            description="Malware score at or above the quarantine threshold",
            predicate=lambda r, t: _score(r, "malware_score") >= t.malware_quarantine,
            action=Action.QUARANTINE,
            classification=ThreatClass.MALWARE,
        ),
        # R2/R3 explicitly stand down for IMPERSONATION. A message whose only
        # evidence is identity deception — no credential ask, no payload, no
        # hostile link — still scores highly on the phishing agent, because
        # identity is one of its four evidence families. Quarantining on that
        # alone destroys legitimate mail from partners and rebranded senders,
        # which is why R5 exists. Without this guard R5 could never be the
        # deciding rule, and a rule that can never fire is a bug.
        PolicyRule(
            id="R2_phishing_quarantine",
            description="Phishing score at or above the quarantine threshold",
            predicate=lambda r, t: _score(r, "phishing_score") >= t.phishing_quarantine
            and r.dominant_class is not ThreatClass.IMPERSONATION,
            action=Action.QUARANTINE,
            classification=ThreatClass.PHISHING,
        ),
        PolicyRule(
            id="R3_url_quarantine",
            description="A link in the message is independently assessed as hostile",
            predicate=lambda r, t: _score(r, "url_score") >= t.phishing_quarantine
            and r.dominant_class is not ThreatClass.IMPERSONATION,
            action=Action.QUARANTINE,
            classification=ThreatClass.PHISHING,
        ),
        PolicyRule(
            id="R4_bec_review",
            description="BEC score at or above the review threshold — money movement needs a human",
            predicate=lambda r, t: _score(r, "bec_score") >= t.bec_review,
            action=Action.HIGH_RISK_REVIEW,
            classification=ThreatClass.BEC,
            requires_human_review=True,
        ),
        PolicyRule(
            id="R5_impersonation_review",
            description="Identity impersonation without a payload — quarantine loses legitimate mail, so review",
            predicate=lambda r, t: r.dominant_class is ThreatClass.IMPERSONATION
            and r.risk_score >= t.impersonation_review,
            action=Action.HIGH_RISK_REVIEW,
            classification=ThreatClass.IMPERSONATION,
            requires_human_review=True,
        ),
        PolicyRule(
            id="R6_composite_escalation",
            description="Several medium-confidence threat signals corroborate across agents",
            predicate=lambda r, t: sum(
                v for k, v in r.scores.items() if k.endswith("_score") and v >= t.suspicious_floor
            ) >= t.composite_quarantine
            and r.dominant_class is not ThreatClass.IMPERSONATION,
            action=Action.QUARANTINE,
        ),
        PolicyRule(
            id="R7_malware_partial",
            description="Malware evidence below the quarantine bar but well above noise",
            predicate=lambda r, t: t.suspicious_floor <= _score(r, "malware_score") < t.malware_quarantine,
            action=Action.HIGH_RISK_REVIEW,
            classification=ThreatClass.MALWARE,
            requires_human_review=True,
        ),
        PolicyRule(
            id="R8_phishing_partial",
            description="Phishing evidence below the quarantine bar but above the suspicion floor",
            predicate=lambda r, t: t.suspicious_floor <= max(_score(r, "phishing_score"), _score(r, "url_score")) < t.phishing_quarantine,
            action=Action.HIGH_RISK_REVIEW,
            classification=ThreatClass.PHISHING,
            requires_human_review=True,
        ),
        PolicyRule(
            id="R9_bec_partial",
            description="BEC evidence below the review threshold but above the suspicion floor",
            predicate=lambda r, t: t.suspicious_floor <= _score(r, "bec_score") < t.bec_review,
            action=Action.HIGH_RISK_REVIEW,
            classification=ThreatClass.BEC,
            requires_human_review=True,
        ),
        PolicyRule(
            id="R10_spam_junk",
            description="Spam score at or above the junk threshold",
            predicate=lambda r, t: _score(r, "spam_score") >= t.spam_junk,
            action=Action.JUNK,
            classification=ThreatClass.SPAM,
        ),
        PolicyRule(
            id="R11_spam_suspected",
            description="Probable but not certain bulk mail",
            predicate=lambda r, t: t.suspicious_floor <= _score(r, "spam_score") < t.spam_junk,
            action=Action.JUNK,
            classification=ThreatClass.SPAM,
        ),
    ]


class PolicyEngine:
    """Evaluates rules and applies the fail-safe overrides."""

    def __init__(self, settings: Settings | None = None, rules: list[PolicyRule] | None = None) -> None:
        self._settings = settings or get_settings()
        self.thresholds = self._settings.policy
        self.rules = rules or build_rules()

    @staticmethod
    def _unresolved_agents(risk: AggregatedRisk) -> list[str]:
        """Degraded agents that produced no concrete evidence either way."""
        by_name = {v.agent_name: v for v in risk.agent_results}
        unresolved: list[str] = []
        for name in risk.degraded_agents:
            verdict = by_name.get(name)
            if verdict is None or not any(i.source == "tool" for i in verdict.indicators):
                unresolved.append(name)
        return sorted(unresolved)

    @staticmethod
    def _classification_is_unresolved(
        classification: ThreatClass, unresolved: list[str], risk: AggregatedRisk
    ) -> bool:
        """True when the label rests only on an agent that never completed."""
        if classification in {ThreatClass.CLEAN, ThreatClass.SUSPICIOUS}:
            return True
        owners = {name for name in unresolved if _AGENT_CLASS.get(name) is classification}
        if not owners:
            return False
        healthy = {
            v.agent_name for v in risk.agent_results
            if v.agent_name not in unresolved and _AGENT_CLASS.get(v.agent_name) is classification and v.score >= 0.5
        }
        return not healthy

    def decide(self, risk: AggregatedRisk) -> Decision:
        """Score bundle in, enforceable decision out. Pure and deterministic."""
        fired: list[str] = []
        action = Action.DELIVER
        # The aggregator decides WHAT the message is (it has the scores and the
        # indicators); this engine decides what HAPPENS to it. Conflating the
        # two lets a low-priority rule that did not drive the action rewrite the
        # verdict — e.g. a partial-phishing rule relabelling a confirmed BEC.
        classification = ThreatClass.CLEAN
        rule_classification = ThreatClass.CLEAN
        requires_review = False
        reasons: list[str] = list(risk.reasons)

        for rule in self.rules:
            try:
                matched = rule.predicate(risk, self.thresholds)
            except Exception:  # noqa: BLE001 - a broken rule must not open the gate
                matched = False
                reasons.append(f"Policy rule {rule.id} could not be evaluated; ignored")
            if not matched:
                continue
            fired.append(rule.id)
            reasons.append(f"[{rule.id}] {rule.description}")
            if ACTION_SEVERITY[rule.action] > ACTION_SEVERITY[action]:
                action = rule.action
                requires_review = rule.requires_human_review
            elif rule.action == action and rule.requires_human_review:
                requires_review = True
            if rule.classification is not None and _more_severe(rule.classification, rule_classification):
                rule_classification = rule.classification

        # Prefer the aggregator's score-based classification; fall back to the
        # most severe class named by a fired rule.
        classification = risk.dominant_class if risk.dominant_class is not ThreatClass.CLEAN else rule_classification

        # ---- fail-safe overrides (§16) --------------------------------- #
        fail_safe = False
        if risk.coverage < self.thresholds.min_coverage_for_clean and action == Action.DELIVER:
            fail_safe = True
            fired.append("FS1_insufficient_coverage")
            reasons.append(
                f"[FS1] Only {risk.coverage:.0%} of detection agents produced a usable verdict; "
                "a message cannot be marked clean on partial analysis"
            )
            action = Action.HIGH_RISK_REVIEW
            requires_review = True
            classification = ThreatClass.SUSPICIOUS

        # An agent that could not complete has told us nothing. Its fail-safe
        # uncertainty score must not be reported as a positive detection, and it
        # must not be treated as a clean result either.
        unresolved = self._unresolved_agents(risk)
        if unresolved:
            fail_safe = True
            fired.append("FS2_agent_analysis_incomplete")
            reasons.append(
                f"[FS2] {', '.join(unresolved)} did not complete; unresolved risk is escalated rather than delivered"
            )
            if ACTION_SEVERITY[action] < ACTION_SEVERITY[Action.HIGH_RISK_REVIEW]:
                action = Action.HIGH_RISK_REVIEW
                requires_review = True
            if self._classification_is_unresolved(classification, unresolved, risk):
                classification = ThreatClass.SUSPICIOUS

        if action is not Action.DELIVER and classification is ThreatClass.CLEAN:
            classification = risk.dominant_class if risk.dominant_class is not ThreatClass.CLEAN else ThreatClass.SUSPICIOUS

        if not self.thresholds.human_review_enabled and action is Action.HIGH_RISK_REVIEW:
            # Deployment without an analyst queue: escalate rather than release.
            action = Action.QUARANTINE
            requires_review = False
            reasons.append("[FS3] Human review disabled in this deployment; escalated to quarantine")

        if action is Action.DELIVER:
            # Coherence: if nothing was actioned, nothing was judged a threat.
            # Reporting "BEC — delivered" would be an unactionable contradiction
            # in an analyst's queue.
            classification = ThreatClass.CLEAN
            if not reasons:
                reasons.append("No policy rule fired; all detection scores below thresholds")

        return Decision(
            message_id=risk.message_id,
            correlation_id=risk.correlation_id,
            final_classification=classification,
            risk_score=round(risk.risk_score, 4),
            confidence=round(risk.confidence, 4),
            recommended_action=action,
            reasons=reasons,
            agent_results=risk.agent_results,
            policy_rules_fired=fired,
            requires_human_review=requires_review and self.thresholds.human_review_enabled,
            fail_safe_applied=fail_safe,
        )


#: Which agent answers for which threat class, for the unresolved-verdict check.
_AGENT_CLASS: dict[str, ThreatClass] = {
    "malware_agent": ThreatClass.MALWARE,
    "phishing_agent": ThreatClass.PHISHING,
    "bec_agent": ThreatClass.BEC,
    "spam_agent": ThreatClass.SPAM,
    "url_agent": ThreatClass.PHISHING,
}


def _more_severe(candidate: ThreatClass, current: ThreatClass) -> bool:
    try:
        return CLASS_PRIORITY.index(candidate) < CLASS_PRIORITY.index(current)
    except ValueError:  # pragma: no cover
        return False
