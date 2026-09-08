"""Workflow-level tests: topology, concurrency, state, HITL and failure containment."""

from __future__ import annotations

import asyncio
import time

import pytest

from email_security.models.schemas import Action, Decision, Email, HumanReviewResponse, ThreatClass
from email_security.orchestration import EmailSecurityPipeline, IngestionExecutor, PipelinePool, build_components
from email_security.orchestration.workflow import build_workflow


class TestTopology:
    def test_graph_contains_every_node(self):
        pipeline = EmailSecurityPipeline()
        mermaid = pipeline.visualize()
        for node in ("ingestion", "orchestrator", "spam_agent", "phishing_agent", "malware_agent",
                     "bec_agent", "url_agent", "risk_aggregator", "policy_engine", "human_review", "final_decision"):
            assert node in mermaid

    def test_orchestrator_fans_out_to_all_detectors(self):
        mermaid = EmailSecurityPipeline().visualize()
        for agent in ("spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent"):
            assert f"orchestrator --> {agent}" in mermaid

    def test_detectors_fan_in_to_the_aggregator(self):
        mermaid = EmailSecurityPipeline().visualize()
        assert "fan_in" in mermaid
        assert "risk_aggregator" in mermaid

    def test_unknown_agent_is_rejected(self):
        with pytest.raises(ValueError, match="unknown agent"):
            build_components(agent_names=["nope_agent"])

    def test_agent_set_is_configurable(self):
        _workflow, parts = build_workflow(agent_names=["phishing_agent", "malware_agent"])
        assert [d.id for d in parts.detectors] == ["phishing_agent", "malware_agent"]


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_phishing_is_quarantined(self, phishing_email):
        decision = await EmailSecurityPipeline().analyze(phishing_email)
        assert decision.final_classification is ThreatClass.PHISHING
        assert decision.recommended_action is Action.QUARANTINE
        assert "R2_phishing_quarantine" in decision.policy_rules_fired

    @pytest.mark.asyncio
    async def test_benign_mail_is_delivered(self, benign_email):
        decision = await EmailSecurityPipeline().analyze(benign_email)
        assert decision.recommended_action is Action.DELIVER
        assert decision.final_classification is ThreatClass.CLEAN

    @pytest.mark.asyncio
    async def test_bec_is_escalated_to_a_human(self, bec_email):
        decision = await EmailSecurityPipeline().analyze(bec_email)
        assert decision.final_classification is ThreatClass.BEC
        assert decision.requires_human_review is True

    @pytest.mark.asyncio
    async def test_every_agent_reports(self, phishing_email):
        decision = await EmailSecurityPipeline().analyze(phishing_email)
        assert {v.agent_name for v in decision.agent_results} == {
            "spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent"
        }

    @pytest.mark.asyncio
    async def test_trace_covers_the_documented_pipeline(self, phishing_email):
        decision = await EmailSecurityPipeline().analyze(phishing_email)
        stages = [span["stage"] for span in decision.trace]
        for expected in ("EMAIL_RECEIVED", "EMAIL_NORMALIZED", "ORCHESTRATOR_STARTED", "AGENTS_DISPATCHED",
                         "AGENT_RESULTS_COLLECTED", "RISK_AGGREGATED", "POLICY_ENGINE", "POLICY_EVALUATED",
                         "FINAL_DECISION"):
            assert expected in stages, f"missing trace stage {expected}"
        assert all(span["correlation_id"] == decision.correlation_id for span in decision.trace)

    @pytest.mark.asyncio
    async def test_decision_is_json_serialisable(self, phishing_email):
        decision = await EmailSecurityPipeline().analyze(phishing_email)
        restored = Decision.model_validate_json(decision.model_dump_json())
        assert restored.risk_score == decision.risk_score


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_detectors_run_in_one_superstep_not_in_sequence(self, benign_email, monkeypatch):
        """Total agent time must be max(), not sum(). This is the whole point of
        fan-out, so it is asserted rather than assumed."""
        import email_security.agents as agents_pkg

        delay = 0.25
        for cls_name in ("SpamAgent", "PhishingAgent", "MalwareAgent", "BecAgent", "UrlAgent"):
            cls = getattr(agents_pkg, cls_name)
            original = cls.gather_evidence

            def slow(self, email, _original=original):
                time.sleep(delay)  # runs in a worker thread via asyncio.to_thread
                return _original(self, email)

            monkeypatch.setattr(cls, "gather_evidence", slow)

        pipeline = EmailSecurityPipeline()
        started = time.perf_counter()
        await pipeline.analyze(benign_email)
        elapsed = time.perf_counter() - started
        # Sequential execution would take >= 5 * delay.
        assert elapsed < delay * 3, f"agents appear to be running sequentially ({elapsed:.2f}s)"

    @pytest.mark.asyncio
    async def test_pool_analyses_messages_in_parallel(self, benign_email, phishing_email, bec_email):
        pool = PipelinePool(size=3)
        decisions = await asyncio.gather(
            pool.analyze(benign_email), pool.analyze(phishing_email), pool.analyze(bec_email)
        )
        assert [d.final_classification for d in decisions] == [
            ThreatClass.CLEAN, ThreatClass.PHISHING, ThreatClass.BEC
        ]

    @pytest.mark.asyncio
    async def test_single_pipeline_serialises_concurrent_calls_safely(self, benign_email, phishing_email):
        pipeline = EmailSecurityPipeline()
        decisions = await asyncio.gather(pipeline.analyze(benign_email), pipeline.analyze(phishing_email))
        assert len(decisions) == 2
        assert decisions[0].message_id != decisions[1].message_id


class TestFailureContainment:
    @pytest.mark.asyncio
    async def test_a_crashing_agent_does_not_stop_the_pipeline(self, phishing_email, monkeypatch):
        from email_security.agents import MalwareAgent

        def explode(self, email):
            raise RuntimeError("scanner offline")

        monkeypatch.setattr(MalwareAgent, "gather_evidence", explode)
        decision = await EmailSecurityPipeline().analyze(phishing_email)
        assert decision.recommended_action is not Action.DELIVER
        malware = next(v for v in decision.agent_results if v.agent_name == "malware_agent")
        assert malware.degraded is True

    @pytest.mark.asyncio
    async def test_benign_mail_is_held_when_the_malware_agent_fails(self, benign_email, monkeypatch):
        """Fail-safe, not fail-open: an unanalysed message is not a clean one."""
        from email_security.agents import MalwareAgent

        def explode(self, email):
            raise RuntimeError("scanner offline")

        monkeypatch.setattr(MalwareAgent, "gather_evidence", explode)
        decision = await EmailSecurityPipeline().analyze(benign_email)
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW
        assert decision.fail_safe_applied is True
        assert "FS2_agent_analysis_incomplete" in decision.policy_rules_fired
        # The message is not labelled MALWARE on the strength of an analysis
        # that never ran — it is labelled unresolved.
        assert decision.final_classification is ThreatClass.SUSPICIOUS


class TestHumanInTheLoop:
    @pytest.mark.asyncio
    async def test_workflow_suspends_and_resumes_with_the_analyst_decision(self, bec_email):
        pipeline = EmailSecurityPipeline(human_review_mode="request_info")
        result = await pipeline.workflow.run(bec_email)
        events = result.get_request_info_events()
        assert events, "workflow should have suspended for review"
        review = events[0].data
        assert review.proposed_action is Action.HIGH_RISK_REVIEW

        resumed = await pipeline.workflow.run(
            responses={events[0].request_id: HumanReviewResponse(
                decision=Action.QUARANTINE, analyst="soc@contoso.com", rationale="confirmed CEO fraud")}
        )
        decision = resumed.get_outputs()[-1]
        assert decision.recommended_action is Action.QUARANTINE
        assert decision.requires_human_review is False
        assert any("[HUMAN]" in r for r in decision.reasons)

    @pytest.mark.asyncio
    async def test_analyst_release_marks_the_message_clean(self, bec_email):
        pipeline = EmailSecurityPipeline(human_review_mode="request_info")
        result = await pipeline.workflow.run(bec_email)
        event = result.get_request_info_events()[0]
        resumed = await pipeline.workflow.run(
            responses={event.request_id: HumanReviewResponse(decision=Action.DELIVER, analyst="soc@contoso.com",
                                                             rationale="verified by phone with the CEO")}
        )
        decision = resumed.get_outputs()[-1]
        assert decision.recommended_action is Action.DELIVER
        assert decision.final_classification is ThreatClass.CLEAN

    @pytest.mark.asyncio
    async def test_queue_mode_does_not_block(self, bec_email):
        decision = await EmailSecurityPipeline(human_review_mode="queue").analyze(bec_email)
        assert decision.requires_human_review is True
        assert decision.recommended_action is Action.HIGH_RISK_REVIEW


class TestIngestion:
    def test_maps_a_microsoft_graph_message(self):
        graph_message = {
            "id": "AAMkAGI2...",
            "internetMessageId": "<abc@contoso.com>",
            "subject": "Quarterly report",
            "from": {"emailAddress": {"name": "Priya Nandan", "address": "Priya.Nandan@contoso.com"}},
            "replyTo": [{"emailAddress": {"name": "AP", "address": "ap@contoso.com"}}],
            "toRecipients": [{"emailAddress": {"name": "Alex", "address": "alex.morgan@contoso.com"}}],
            "body": {"contentType": "html", "content": "<p>See attached. <a href='https://contoso.com/r'>link</a></p>"},
            "internetMessageHeaders": [{"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=pass"}],
            "attachments": [{"name": "report.pdf", "contentType": "application/pdf", "size": 12345}],
        }
        email = IngestionExecutor.normalize(graph_message, source="graph")
        assert email.message_id == "<abc@contoso.com>"
        assert email.sender.address == "priya.nandan@contoso.com"
        assert email.sender.display_name == "Priya Nandan"
        assert email.reply_to.address == "ap@contoso.com"
        assert email.recipients[0].address == "alex.morgan@contoso.com"
        assert email.header("Authentication-Results").startswith("spf=pass")
        assert email.attachments[0].filename == "report.pdf"

    @pytest.mark.asyncio
    async def test_graph_message_flows_through_the_pipeline(self):
        graph_message = {
            "internetMessageId": "<graph-1@contoso.com>",
            "subject": "Verify your account now",
            "from": {"emailAddress": {"name": "Microsoft Account Team", "address": "security@micros0ft-login.com"}},
            "toRecipients": [{"emailAddress": {"name": "Alex", "address": "alex.morgan@contoso.com"}}],
            "body": {"contentType": "text",
                     "content": "Verify your account or it will be suspended: https://micros0ft-login.com/verify"},
            "internetMessageHeaders": [{"name": "Authentication-Results", "value": "spf=fail; dkim=none; dmarc=fail (p=reject)"}],
        }
        email = IngestionExecutor.normalize(graph_message, source="graph")
        decision = await EmailSecurityPipeline().analyze(email)
        assert decision.recommended_action is Action.QUARANTINE

    def test_urls_are_extracted_during_normalization(self):
        email = Email.model_validate({
            "sender": "a@b.com",
            "body_text": "click https://example.com/x now",
        })
        request = IngestionExecutor._to_request(email)
        assert request.email.urls == ["https://example.com/x"]

    def test_attachment_hashes_are_computed_during_normalization(self):
        email = Email.model_validate({
            "sender": "a@b.com",
            "attachments": [{"filename": "x.pdf", "content_type": "application/pdf", "size_bytes": 10}],
        })
        request = IngestionExecutor._to_request(email)
        assert request.email.attachments[0].sha256
