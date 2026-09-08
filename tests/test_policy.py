"""Policy-engine tests.

These matter more than the agent tests: the policy engine is the only component
that decides what happens to a message, it contains no model, and it must stay
fully deterministic and auditable.
"""

from __future__ import annotations

from email_security.config.settings import get_settings
from email_security.models.schemas import Action, AgentVerdict, AggregatedRisk, Indicator, ThreatClass
from email_security.policy import ACTION_SEVERITY, PolicyEngine, build_rules


def risk(**scores) -> AggregatedRisk:
    coverage = scores.pop("coverage", 1.0)
    degraded = scores.pop("degraded_agents", [])
    dominant = scores.pop("dominant_class", ThreatClass.CLEAN)
    return AggregatedRisk(
        message_id="m", correlation_id="c", scores=scores, dominant_class=dominant,
        risk_score=max(scores.values(), default=0.0), confidence=0.9,
        coverage=coverage, degraded_agents=degraded,
    )


class TestThresholds:
    def test_malware_quarantines(self):
        decision = PolicyEngine().decide(risk(malware_score=0.93, dominant_class=ThreatClass.MALWARE))
        assert decision.recommended_action is Action.QUARANTINE
        assert "R1_malware_quarantine" in decision.policy_rules_fired

    def test_phishing_quarantines(self):
        decision = PolicyEngine().decide(risk(phishing_score=0.96, dominant_class=ThreatClass.PHISHING))
        assert decision.recommended_action is Action.QUARANTINE
        assert decision.final_classification is ThreatClass.PHISHING

    def test_bec_goes_to_human_review(self):
        decision = PolicyEngine().decide(risk(bec_score=0.94, dominant_class=ThreatClass.BEC))
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW
        assert decision.requires_human_review is True

    def test_spam_is_junked_not_quarantined(self):
        decision = PolicyEngine().decide(risk(spam_score=0.91, dominant_class=ThreatClass.SPAM))
        assert decision.recommended_action is Action.JUNK

    def test_clean_mail_is_delivered(self):
        decision = PolicyEngine().decide(risk(spam_score=0.05, phishing_score=0.02))
        assert decision.recommended_action is Action.DELIVER
        assert decision.final_classification is ThreatClass.CLEAN
        assert decision.policy_rules_fired == []

    def test_composite_escalation_on_corroborating_medium_signals(self):
        decision = PolicyEngine().decide(risk(phishing_score=0.6, bec_score=0.6, spam_score=0.6))
        assert "R6_composite_escalation" in decision.policy_rules_fired
        assert decision.recommended_action is Action.QUARANTINE

    def test_thresholds_are_configurable(self):
        settings = get_settings(refresh=True)
        settings.policy.phishing_quarantine = 0.50
        decision = PolicyEngine(settings).decide(risk(phishing_score=0.55, dominant_class=ThreatClass.PHISHING))
        assert decision.recommended_action is Action.QUARANTINE
        get_settings(refresh=True)  # restore

    def test_action_only_escalates(self):
        # A junk-level rule must never downgrade a quarantine decision.
        decision = PolicyEngine().decide(risk(malware_score=0.95, spam_score=0.95, dominant_class=ThreatClass.MALWARE))
        assert decision.recommended_action is Action.QUARANTINE


class TestFailSafe:
    def test_partial_coverage_cannot_be_marked_clean(self):
        decision = PolicyEngine().decide(risk(spam_score=0.0, coverage=0.6))
        assert decision.fail_safe_applied is True
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW
        assert "FS1_insufficient_coverage" in decision.policy_rules_fired

    def test_degraded_agent_never_fails_open(self):
        decision = PolicyEngine().decide(risk(spam_score=0.0, degraded_agents=["malware_agent"]))
        assert decision.fail_safe_applied is True
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW
        assert "FS2_agent_analysis_incomplete" in decision.policy_rules_fired

    def test_unresolved_agent_is_not_reported_as_a_detection(self):
        """A malware agent that crashed has told us nothing; labelling the message
        MALWARE on its fail-safe uncertainty score would be a fabricated verdict."""
        decision = PolicyEngine().decide(
            risk(malware_score=0.5, degraded_agents=["malware_agent"], dominant_class=ThreatClass.MALWARE)
        )
        assert decision.final_classification is ThreatClass.SUSPICIOUS
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW

    def test_a_healthy_agent_detection_survives_another_agent_degrading(self):
        healthy = AgentVerdict(
            agent_name="phishing_agent", classification=ThreatClass.PHISHING, score=0.95, confidence=0.9,
            indicators=[Indicator(id="sender_lookalike_domain", description="d", weight=0.8, source="tool")],
        )
        bundle = risk(phishing_score=0.95, degraded_agents=["url_agent"], dominant_class=ThreatClass.PHISHING)
        bundle.agent_results = [healthy]
        decision = PolicyEngine().decide(bundle)
        assert decision.final_classification is ThreatClass.PHISHING
        assert decision.recommended_action is Action.QUARANTINE

    def test_degraded_malware_agent_upgrades_a_junk_verdict(self):
        decision = PolicyEngine().decide(
            risk(spam_score=0.9, degraded_agents=["malware_agent"], dominant_class=ThreatClass.SPAM)
        )
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW

    def test_review_becomes_quarantine_without_an_analyst_queue(self):
        settings = get_settings(refresh=True)
        settings.policy.human_review_enabled = False
        decision = PolicyEngine(settings).decide(risk(bec_score=0.95, dominant_class=ThreatClass.BEC))
        assert decision.recommended_action is Action.QUARANTINE
        assert decision.requires_human_review is False
        get_settings(refresh=True)

    def test_a_broken_rule_does_not_open_the_gate(self):
        from email_security.policy.risk_policy import PolicyRule

        def explode(_r, _t):
            raise ValueError("boom")

        rules = [PolicyRule(id="BAD", description="broken", predicate=explode, action=Action.DELIVER), *build_rules()]
        decision = PolicyEngine(rules=rules).decide(risk(malware_score=0.95, dominant_class=ThreatClass.MALWARE))
        assert decision.recommended_action is Action.QUARANTINE
        assert any("BAD" in r for r in decision.reasons)


class TestDecisionCoherence:
    def test_delivered_mail_is_labelled_clean(self):
        # Reporting "BEC — delivered" would be an unactionable contradiction.
        decision = PolicyEngine().decide(risk(bec_score=0.4, dominant_class=ThreatClass.BEC))
        if decision.recommended_action is Action.DELIVER:
            assert decision.final_classification is ThreatClass.CLEAN

    def test_every_action_has_a_recorded_reason(self):
        decision = PolicyEngine().decide(risk(phishing_score=0.95, dominant_class=ThreatClass.PHISHING))
        assert decision.reasons
        assert all(isinstance(r, str) for r in decision.reasons)

    def test_action_severity_is_total_and_ordered(self):
        assert ACTION_SEVERITY[Action.DELIVER] < ACTION_SEVERITY[Action.JUNK]
        assert ACTION_SEVERITY[Action.JUNK] < ACTION_SEVERITY[Action.HIGH_RISK_REVIEW]
        assert ACTION_SEVERITY[Action.HIGH_RISK_REVIEW] < ACTION_SEVERITY[Action.QUARANTINE]
        assert len(ACTION_SEVERITY) == len(Action)


class TestImpersonationProportionality:
    """Identity deception with no payload gets a human, not a quarantine.

    The phishing agent scores impersonation highly by design — identity is one
    of its four evidence families — so without an explicit guard R2 would
    quarantine every rebranded partner and R5 could never fire at all.
    """

    def test_impersonation_goes_to_review_not_quarantine(self):
        decision = PolicyEngine().decide(
            risk(phishing_score=0.95, url_score=0.0, dominant_class=ThreatClass.IMPERSONATION)
        )
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW
        assert decision.final_classification is ThreatClass.IMPERSONATION
        assert "R5_impersonation_review" in decision.policy_rules_fired
        assert "R2_phishing_quarantine" not in decision.policy_rules_fired

    def test_real_phishing_still_quarantines(self):
        decision = PolicyEngine().decide(risk(phishing_score=0.95, dominant_class=ThreatClass.PHISHING))
        assert decision.recommended_action is Action.QUARANTINE
        assert "R2_phishing_quarantine" in decision.policy_rules_fired

    def test_impersonation_carrying_a_payload_is_not_downgraded(self):
        # A malicious attachment outranks the impersonation pretext entirely.
        decision = PolicyEngine().decide(
            risk(phishing_score=0.95, malware_score=0.95, dominant_class=ThreatClass.MALWARE)
        )
        assert decision.recommended_action is Action.QUARANTINE
