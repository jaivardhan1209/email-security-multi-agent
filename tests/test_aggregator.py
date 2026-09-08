"""Risk-aggregator tests: score merging, classification and coverage."""

from __future__ import annotations

import time

import pytest

from email_security.models.messages import AnalysisRequest
from email_security.models.schemas import AgentVerdict, Indicator, ThreatClass
from email_security.orchestration.executors import RiskAggregatorExecutor
from tests.conftest import make_email

AGENTS = ["spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent"]


def verdict(name: str, score: float, *, indicators=(), degraded=False, cls=ThreatClass.CLEAN) -> AgentVerdict:
    return AgentVerdict(
        agent_name=name, classification=cls, score=score, confidence=0.8, degraded=degraded,
        indicators=[Indicator(id=i, description=i, weight=0.5) for i in indicators],
    )


def request_for(email=None) -> AnalysisRequest:
    email = email or make_email()
    return AnalysisRequest(email=email, correlation_id="c", selected_agents=list(AGENTS),
                           started_at=time.perf_counter())


@pytest.fixture
def aggregator() -> RiskAggregatorExecutor:
    return RiskAggregatorExecutor(AGENTS)


class TestScoreMerging:
    def test_top_score_is_not_diluted_by_silent_agents(self, aggregator):
        verdicts = [verdict("malware_agent", 0.95)] + [verdict(n, 0.0) for n in AGENTS if n != "malware_agent"]
        risk = aggregator.build_risk(verdicts, request_for())
        assert risk.risk_score == pytest.approx(0.95)

    def test_corroboration_lifts_the_score(self, aggregator):
        alone = aggregator.build_risk(
            [verdict("phishing_agent", 0.8)] + [verdict(n, 0.0) for n in AGENTS if n != "phishing_agent"],
            request_for(),
        )
        corroborated = aggregator.build_risk(
            [verdict("phishing_agent", 0.8), verdict("url_agent", 0.7), verdict("bec_agent", 0.6),
             verdict("spam_agent", 0.0), verdict("malware_agent", 0.0)],
            request_for(),
        )
        assert corroborated.risk_score > alone.risk_score

    def test_score_never_exceeds_one(self, aggregator):
        verdicts = [verdict(n, 0.99) for n in AGENTS]
        assert aggregator.build_risk(verdicts, request_for()).risk_score <= 1.0


class TestClassification:
    def test_malware_outranks_the_pretext_that_carried_it(self, aggregator):
        verdicts = [verdict("malware_agent", 0.92), verdict("phishing_agent", 0.99),
                    verdict("bec_agent", 0.0), verdict("spam_agent", 0.0), verdict("url_agent", 0.5)]
        assert aggregator.build_risk(verdicts, request_for()).dominant_class is ThreatClass.MALWARE

    def test_identity_deception_without_an_ask_is_impersonation(self, aggregator):
        verdicts = [
            verdict("bec_agent", 0.7, indicators=["executive_impersonation_freemail"]),
            verdict("phishing_agent", 0.6, indicators=["brand_impersonation_display_name"]),
            verdict("spam_agent", 0.0), verdict("malware_agent", 0.0), verdict("url_agent", 0.0),
        ]
        assert aggregator.build_risk(verdicts, request_for()).dominant_class is ThreatClass.IMPERSONATION

    def test_identity_deception_with_a_financial_ask_is_bec(self, aggregator):
        verdicts = [
            verdict("bec_agent", 0.9, indicators=["executive_impersonation_freemail", "financial:wire_transfer_request"]),
            verdict("phishing_agent", 0.2), verdict("spam_agent", 0.0),
            verdict("malware_agent", 0.0), verdict("url_agent", 0.0),
        ]
        assert aggregator.build_risk(verdicts, request_for()).dominant_class is ThreatClass.BEC

    def test_quiet_agents_produce_a_clean_classification(self, aggregator):
        assert aggregator.build_risk([verdict(n, 0.1) for n in AGENTS], request_for()).dominant_class is ThreatClass.CLEAN


class TestCoverage:
    def test_missing_agent_reduces_coverage_and_is_reported_degraded(self, aggregator):
        verdicts = [verdict(n, 0.0) for n in AGENTS if n != "malware_agent"]
        risk = aggregator.build_risk(verdicts, request_for())
        assert risk.coverage == pytest.approx(0.8)
        assert "malware_agent" in risk.degraded_agents
        assert any("malware_agent" in r for r in risk.reasons)

    def test_degraded_agent_is_listed(self, aggregator):
        verdicts = [verdict(n, 0.0, degraded=(n == "url_agent")) for n in AGENTS]
        risk = aggregator.build_risk(verdicts, request_for())
        assert risk.degraded_agents == ["url_agent"]
        assert risk.coverage == pytest.approx(1.0)

    def test_confidence_is_scaled_down_by_missing_coverage(self, aggregator):
        full = aggregator.build_risk([verdict(n, 0.9) for n in AGENTS], request_for())
        partial = aggregator.build_risk([verdict(n, 0.9) for n in AGENTS[:2]], request_for())
        assert partial.confidence < full.confidence
