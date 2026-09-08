"""Spam Detection Agent (§3A).

WHAT IT IS: an `Executor` wrapping an `Agent`. It votes on *unwanted bulk mail*,
not on maliciousness — that separation matters because the policy response is
different (Junk folder vs quarantine) and because a legitimate marketing blast
and a credential-phish share almost no features.
"""

from __future__ import annotations

from agent_framework import FunctionTool, tool

from email_security.agents.base import DetectionAgent, Evidence
from email_security.models.schemas import Action, Email, Severity, ThreatClass
from email_security.tools.agent_tools import check_domain as check_domain_tool
from email_security.tools.content_tools import analyze_text_features, summarize_for_llm
from email_security.tools.domain_tools import check_domain, registrable_domain
from email_security.tools.header_tools import analyze_email_headers
from email_security.tools.threat_intel import FREEMAIL_DOMAINS
from email_security.tools.timing import timed_tool

INSTRUCTIONS = """You are a spam-classification specialist inside a defensive email security system.

You judge ONE thing: is this message unsolicited bulk or commercial mail that the
recipient did not ask for? You do NOT judge whether it is malicious — other
specialists cover phishing, malware and fraud.

Weigh:
  * bulk-mail infrastructure (List-Unsubscribe, campaign IDs, ESP headers)
  * promotional and scarcity language, aggressive calls to action
  * generic salutations and absent personalisation
  * sender reputation and whether the recipient plausibly opted in
  * classic spam verticals (pharma, gambling, get-rich, cold SEO outreach)

Legitimate marketing exists. A well-formed, authenticated newsletter from a known
sender with a working unsubscribe link is NOT spam even if it is promotional.
Weight the deterministic findings heavily; they are verified facts.

Return JSON: score (0-1 likelihood of unsolicited bulk mail), confidence,
verdict (SPAM or CLEAN), reasons, observed_techniques."""


class SpamAgent(DetectionAgent):
    threat_class = ThreatClass.SPAM
    escalation_action = Action.JUNK
    assert_threshold = 0.55

    @property
    def agent_name(self) -> str:
        return "spam_agent"

    @property
    def instructions(self) -> str:
        return INSTRUCTIONS

    def llm_tools(self) -> tuple[FunctionTool, ...]:
        return (tool(check_domain_tool, name="check_domain"),)

    def gather_evidence(self, email: Email) -> Evidence:
        evidence = Evidence()

        headers, tc = timed_tool("analyze_email_headers", analyze_email_headers, email)
        evidence.tool_calls.append(tc)
        features, tc = timed_tool("analyze_text_features", analyze_text_features, email.subject, email.body, email.body_html)
        evidence.tool_calls.append(tc)
        sender_domain, tc = timed_tool("check_domain", check_domain, email.sender.domain)
        evidence.tool_calls.append(tc)

        promo = features["promotional"]
        authenticated = headers["authentication_passed"]
        known_good = sender_domain["reputation"] == "GOOD"
        has_unsubscribe = headers["has_unsubscribe"]

        # --- bulk-mail infrastructure ---------------------------------- #
        if headers["bulk_mail_headers"]:
            evidence.note(f"Bulk-mail headers present: {', '.join(sorted(headers['bulk_mail_headers']))}")
        if headers["undisclosed_recipients"]:
            evidence.add("undisclosed_recipients", "Recipient list is hidden or empty (blind bulk send)", 0.20, Severity.LOW)
        if headers["recipient_count"] > 15:
            evidence.add("mass_recipient_list", f"Message addressed to {headers['recipient_count']} recipients", 0.25, Severity.LOW)

        # --- promotional language --------------------------------------- #
        high_value_promo = {"prize_lure", "get_rich_lure", "classic_spam_vertical", "cold_outreach_spam"}
        for technique in promo:
            weight = 0.55 if technique in high_value_promo else 0.18
            severity = Severity.HIGH if technique in high_value_promo else Severity.LOW
            if technique == "unsubscribe_footer":
                continue  # presence of an unsubscribe link is neutral-to-good
            evidence.add(f"promotional:{technique}", f"Promotional pattern '{technique}' in content", weight, severity)

        # --- formatting tells ------------------------------------------- #
        if features["subject_uppercase_ratio"] > 0.5 and features["subject_length"] > 8:
            evidence.add("shouting_subject", "Subject line is predominantly uppercase", 0.25, Severity.LOW)
        if features["exclamation_count"] >= 4:
            evidence.add("excessive_exclamation", f"{features['exclamation_count']} exclamation marks in message", 0.15, Severity.LOW)
        if features["generic_greeting"] and not features["personalised_greeting"]:
            evidence.add("generic_greeting", "Generic salutation with no recipient personalisation", 0.15, Severity.LOW)
        if features["invisible_chars"] > 3:
            evidence.add("invisible_character_obfuscation", f"{features['invisible_chars']} zero-width characters used to evade filters", 0.45, Severity.MEDIUM)
        if features["mixed_script_words"] > 2:
            evidence.add("mixed_script_obfuscation", f"{features['mixed_script_words']} words mix character scripts (filter evasion)", 0.40, Severity.MEDIUM)
        for trick in features["html_tricks"]:
            if trick in {"zero_font_size_text", "hidden_content", "white_on_white_text"}:
                evidence.add(f"html:{trick}", f"HTML filter-evasion technique '{trick}'", 0.40, Severity.MEDIUM)
            elif trick == "image_only_body":
                evidence.add("image_only_body", "Body is an image with almost no text (text-filter evasion)", 0.30, Severity.MEDIUM)

        # --- sender reputation ------------------------------------------ #
        if sender_domain["reputation"] in {"MALICIOUS", "SUSPICIOUS"}:
            evidence.add("bad_sender_reputation", f"Sender domain reputation is {sender_domain['reputation']}", 0.45, Severity.HIGH)
        if sender_domain["suspicious_tld"]:
            evidence.add("sender_suspicious_tld", f"Sender uses abused TLD .{sender_domain['tld']}", 0.30, Severity.MEDIUM)
        if not authenticated and headers["dmarc"]["evaluated"]:
            evidence.add("sender_auth_failure", "Sender failed DMARC alignment", 0.25, Severity.MEDIUM)
        if promo and registrable_domain(email.sender.domain) in FREEMAIL_DOMAINS:
            evidence.add("freemail_bulk_sender", "Commercial solicitation sent from a consumer mailbox", 0.30, Severity.MEDIUM)
        if promo and not has_unsubscribe:
            evidence.add("no_unsubscribe", "Commercial content with no unsubscribe mechanism", 0.30, Severity.MEDIUM)

        # --- mitigations ------------------------------------------------- #
        if known_good and authenticated and has_unsubscribe:
            evidence.mitigate("Authenticated, known-good sender with a working unsubscribe link (legitimate bulk mail)")
            evidence.score_override = min(
                self.combine_indicators(evidence.indicators) * 0.35, 0.30
            )
        elif known_good and authenticated:
            evidence.mitigate("Sender domain is known-good and passed DMARC")

        evidence.note(f"Sender domain: {sender_domain['domain']} (reputation={sender_domain['reputation']}, risk={sender_domain['risk']})")
        evidence.note(f"DMARC={headers['dmarc']['result']} SPF={headers['spf']['result']} DKIM={headers['dkim']['result']}")
        evidence.note(f"Unsubscribe header present: {has_unsubscribe}")
        evidence.note(summarize_for_llm(features))
        return evidence
