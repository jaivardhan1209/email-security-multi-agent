"""Detection-agent tests.

Each agent is checked on three axes: it fires on its own speciality, it stays
quiet on benign mail, and it fails safe when its tools break.
"""

from __future__ import annotations

import time

import pytest

from email_security.agents import AGENT_REGISTRY, BecAgent, MalwareAgent, PhishingAgent, SpamAgent, UrlAgent
from email_security.agents.base import FAIL_SAFE_UNCERTAINTY, DetectionAgent, Evidence
from email_security.models.messages import AnalysisRequest
from email_security.models.schemas import Attachment, LLMAssessment
from tests.conftest import make_email


def det(agent: DetectionAgent, email) -> float:
    evidence = agent.gather_evidence(email)
    if evidence.score_override is not None:
        return evidence.score_override
    return agent.combine_indicators(evidence.indicators)


def ids(agent: DetectionAgent, email) -> set[str]:
    return {i.id for i in agent.gather_evidence(email).indicators}


def request_for(email) -> AnalysisRequest:
    return AnalysisRequest(email=email, correlation_id="c", selected_agents=list(AGENT_REGISTRY),
                           started_at=time.perf_counter())


class TestSpamAgent:
    def test_fires_on_bulk_promotional_mail(self):
        email = make_email(
            sender="deals@megadeals-outlet.top", recipients=[],
            subject="FINAL HOURS!!! 70% OFF EVERYTHING", headers={},
            body_text="Dear Customer, limited time flash sale. Buy now! Work from home and earn $5000!",
        )
        assert det(SpamAgent("spam_agent"), email) >= 0.85

    def test_quiet_on_internal_mail(self, benign_email):
        assert det(SpamAgent("spam_agent"), benign_email) == 0.0

    def test_authenticated_newsletter_with_unsubscribe_is_suppressed(self):
        email = make_email(
            sender="newsletter@substack.com",
            subject="Issue #241: how large teams do incident review",
            body_html="<p>This week: incident review. <a href='https://substack.com/p/241'>Read online</a> "
                      "<a href='https://substack.com/unsub'>Unsubscribe</a></p>",
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=substack.com; dkim=pass header.d=substack.com; dmarc=pass",
                     "List-Unsubscribe": "<https://substack.com/unsub>", "Precedence": "bulk"},
        )
        assert det(SpamAgent("spam_agent"), email) < 0.55


class TestPhishingAgent:
    def test_fires_on_credential_phish(self, phishing_email):
        agent = PhishingAgent("phishing_agent")
        assert det(agent, phishing_email) >= 0.9
        found = ids(agent, phishing_email)
        assert "sender_lookalike_domain" in found
        assert "multi_family_correlation" in found

    def test_quiet_on_genuine_security_notification(self):
        email = make_email(
            sender='"Microsoft account team" <noreply@accountprotection.microsoft.com>',
            subject="New sign-in to your Microsoft account",
            body_text="We noticed a new sign-in. If this was you, no action is needed. "
                      "Review activity at https://account.microsoft.com/security",
            urls=["https://account.microsoft.com/security"],
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass (p=reject)"},
        )
        assert det(PhishingAgent("phishing_agent"), email) < 0.35

    def test_authentication_failure_alone_is_not_actionable(self):
        # Forwarders and mailing lists break DMARC constantly; on its own that
        # must stay below the action floor.
        email = make_email(
            sender="updates@some-vendor.example",
            subject="Monthly product update",
            body_text="Here is what shipped this month. Nothing else to see.",
            headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"},
        )
        assert det(PhishingAgent("phishing_agent"), email) < 0.5

    def test_detects_display_versus_destination_deception(self):
        email = make_email(
            sender="helpdesk@0ffice365-support.com", subject="Password expires today",
            body_html="<a href='https://0ffice365-support.com/reauth'>https://login.microsoftonline.com/</a>",
            headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"},
        )
        assert "display_destination_mismatch" in ids(PhishingAgent("phishing_agent"), email)

    def test_trusted_sender_does_not_launder_a_hostile_redirect(self):
        email = make_email(
            sender='"LinkedIn" <notifications@linkedin.com>', subject="You appeared in 9 searches",
            urls=["https://linkedin.com/comm/redirect?url=https://account-verify-micrsoft.com/login"],
            body_text="See who's viewing your profile.",
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=linkedin.com; dkim=pass header.d=linkedin.com; dmarc=pass"},
        )
        assert "redirect_to_hostile_destination" in ids(PhishingAgent("phishing_agent"), email)


class TestMalwareAgent:
    def test_fires_on_double_extension(self, malware_email):
        agent = MalwareAgent("malware_agent")
        assert det(agent, malware_email) >= 0.9
        assert "double_extension" in ids(agent, malware_email)

    def test_known_bad_hash_pins_the_score(self):
        email = make_email(attachments=[Attachment(
            filename="doc.pdf", content_type="application/pdf", size_bytes=0, content=b"",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")])
        assert det(MalwareAgent("malware_agent"), email) >= 0.95

    def test_enable_content_lure_is_scored_only_with_a_payload(self):
        with_payload = make_email(
            body_text="Open the attachment and click Enable Content to view your figures.",
            attachments=[Attachment(filename="payslip.xlsm", content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                                    size_bytes=90000, static_indicators=["auto_open_macro"])],
        )
        without = make_email(body_text="Open the attachment and click Enable Content to view your figures.")
        agent = MalwareAgent("malware_agent")
        assert "enable_content_lure" in ids(agent, with_payload)
        assert "enable_content_lure" not in ids(agent, without)

    def test_ordinary_office_attachment_is_not_malware(self):
        email = make_email(attachments=[Attachment(
            filename="Q3_Forecast.pptx",
            content_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
            size_bytes=3_211_264)])
        assert det(MalwareAgent("malware_agent"), email) < 0.35

    def test_payload_link_without_an_attachment(self):
        email = make_email(
            body_text="Reschedule: https://cdn-delivery-files.xyz/dhl/rescheduler.exe",
            urls=["https://cdn-delivery-files.xyz/dhl/rescheduler.exe"],
            headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"},
        )
        assert det(MalwareAgent("malware_agent"), email) >= 0.8


class TestBecAgent:
    def test_fires_on_the_ceo_fraud_triad(self, bec_email):
        agent = BecAgent("bec_agent")
        assert det(agent, bec_email) >= 0.9
        found = ids(agent, bec_email)
        assert "executive_impersonation_freemail" in found
        assert "bec_triad" in found or "bec_dyad" in found

    def test_quiet_on_authenticated_internal_executive_mail(self):
        email = make_email(
            sender='"Robert Chen" <robert.chen@contoso.com>',
            subject="Re: board pack",
            body_text="Alex, could you send me the signed board pack when you get a chance? No rush.",
        )
        assert det(BecAgent("bec_agent"), email) < 0.35

    def test_vendor_lookalike_domain_is_caught(self):
        email = make_email(
            sender='"Sonia Bright" <s.bright@northwlnd-traders.com>', reply_to="accounts@northwlnd-traders.com",
            subject="Re: Invoice NT-88421 — updated remittance details",
            body_text="Please update the bank details and route the outstanding payment to the new account.",
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=northwlnd-traders.com; dkim=pass header.d=northwlnd-traders.com; dmarc=pass"},
        )
        assert det(BecAgent("bec_agent"), email) >= 0.7

    def test_authenticated_vendor_does_not_excuse_impersonating_our_executive(self):
        email = make_email(
            sender='"Robert Chen" <robert.chen@northwind-traders.com>',
            subject="Quick favour",
            body_text="Are you at your desk? I need a quick favour.",
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=northwind-traders.com; dkim=pass header.d=northwind-traders.com; dmarc=pass"},
        )
        assert "named_executive_from_external_domain" in ids(BecAgent("bec_agent"), email)

    def test_engagement_probe_is_detected(self):
        email = make_email(
            sender='"Robert Chen" <r.chen.contoso@gmail.com>', subject="Are you at your desk?",
            body_text="Alex, are you at your desk? I need you to handle something urgently. Robert Chen, CEO",
            headers={"Authentication-Results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass"},
        )
        assert "engagement_probe" in ids(BecAgent("bec_agent"), email)


class TestUrlAgent:
    def test_quiet_when_there_are_no_links(self, benign_email):
        evidence = UrlAgent("url_agent").gather_evidence(benign_email)
        assert evidence.indicators == []
        assert evidence.mitigating

    def test_fires_on_hostile_links(self, phishing_email):
        assert det(UrlAgent("url_agent"), phishing_email) >= 0.9


class TestFailSafeBehaviour:
    @pytest.mark.asyncio
    async def test_tool_failure_produces_a_degraded_uncertain_verdict(self, benign_email, monkeypatch):
        agent = MalwareAgent("malware_agent")

        def explode(_email):
            raise RuntimeError("attachment scanner unavailable")

        monkeypatch.setattr(agent, "gather_evidence", explode)
        verdict = await agent.run_analysis(request_for(benign_email))
        assert verdict.degraded is True
        assert verdict.score >= FAIL_SAFE_UNCERTAINTY
        assert any("tool_failure" in e for e in verdict.errors)

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_deterministic_evidence(self, phishing_email, monkeypatch):
        agent = PhishingAgent("phishing_agent")

        async def broken(*_a, **_k):
            raise RuntimeError("model unreachable")

        monkeypatch.setattr(agent, "_reason", lambda *a, **k: broken())
        verdict = await agent.run_analysis(request_for(phishing_email))
        assert verdict.degraded is True
        assert verdict.llm_used is False
        # The deterministic layer still detected the threat.
        assert verdict.score >= 0.9

    @pytest.mark.asyncio
    async def test_llm_timeout_is_bounded_and_degrades(self, benign_email, monkeypatch):
        import asyncio

        agent = SpamAgent("spam_agent")
        agent._settings.agents.timeout_seconds = 0.05
        agent._settings.agents.retries = 0

        class SlowAgent:
            async def run(self, *_a, **_k):
                await asyncio.sleep(5)

        monkeypatch.setattr(agent, "_get_agent", lambda: SlowAgent())
        verdict = await agent.run_analysis(request_for(benign_email))
        assert verdict.degraded is True
        assert any("timeout" in e for e in verdict.errors)


class TestFusion:
    def test_llm_cannot_talk_the_system_out_of_hard_evidence(self):
        agent = MalwareAgent("malware_agent")
        floor = agent._settings.agents.deterministic_floor_ratio
        exonerating = LLMAssessment(score=0.0, confidence=0.99, verdict="CLEAN", reasons=["looks fine to me"])
        fused, _ = agent.fuse(0.95, exonerating, Evidence())
        assert fused >= 0.95 * floor

    def test_llm_can_raise_a_score_freely(self):
        agent = PhishingAgent("phishing_agent")
        alarming = LLMAssessment(score=1.0, confidence=0.9, verdict="PHISHING", reasons=["novel lure"])
        fused, _ = agent.fuse(0.2, alarming, Evidence())
        assert fused > 0.2

    def test_agreement_raises_confidence_more_than_disagreement(self):
        agent = PhishingAgent("phishing_agent")
        _, agree = agent.fuse(0.9, LLMAssessment(score=0.9, confidence=0.9), Evidence())
        _, disagree = agent.fuse(0.9, LLMAssessment(score=0.1, confidence=0.9), Evidence())
        assert agree > disagree

    def test_malformed_model_output_is_clamped(self):
        wild = LLMAssessment.model_construct(score=7.5, confidence=-3.0, verdict="?", reasons=["x" * 900], observed_techniques=[])
        cleaned = DetectionAgent._sanitize(wild)
        assert 0.0 <= cleaned.score <= 1.0
        assert 0.0 <= cleaned.confidence <= 1.0
        assert len(cleaned.reasons[0]) <= 300

    def test_salvages_json_embedded_in_prose(self):
        text = 'Sure! Here is my analysis:\n```json\n{"score": 0.8, "confidence": 0.7, "verdict": "PHISHING"}\n```\nHope that helps.'
        salvaged = DetectionAgent._salvage(text)
        assert salvaged is not None
        assert salvaged.score == pytest.approx(0.8)
