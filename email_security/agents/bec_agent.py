"""BEC / Impersonation Agent (§3D).

Business Email Compromise is the hardest class in this system and the reason a
purely URL/attachment-driven filter is insufficient. A BEC message frequently
has: no attachment, no link, valid SPF (the attacker owns the sending domain),
and perfect grammar. The only signals are *relational and behavioural*:

  who the sender claims to be  vs  the mailbox they are using
  what is being requested      (money movement, credential-free but financial)
  how verification is discouraged (secrecy, unreachability, urgency)
  whether the conversation context is real (thread hijack, fresh lookalike domain)

That is why this agent leans hardest on the LLM layer: the deterministic rules
find the structural tells, the model reads the social dynamics.
"""

from __future__ import annotations

import re

from agent_framework import FunctionTool, tool

from email_security.agents.base import DetectionAgent, Evidence
from email_security.models.schemas import Action, Email, Severity, ThreatClass
from email_security.tools.agent_tools import check_domain as check_domain_tool
from email_security.tools.agent_tools import check_lookalike_domain as check_lookalike_tool
from email_security.tools.content_tools import analyze_text_features, summarize_for_llm
from email_security.tools.domain_tools import (
    check_domain,
    check_protected_domains,
    detect_lookalike_domain,
    registrable_domain,
)
from email_security.tools.header_tools import analyze_email_headers
from email_security.tools.timing import timed_tool

INSTRUCTIONS = """You are a business-email-compromise and impersonation specialist inside a
defensive email security system.

Determine whether this message is an attempt to defraud the organisation by
impersonating a trusted party. Cover: CEO/executive fraud, vendor and supplier
impersonation, invoice and payment fraud, payroll diversion, and gift-card scams.

BEC messages often have NO links and NO attachments and may pass SPF, because the
attacker controls the sending domain. Judge the relationship and the request:
  * does the sender claim authority they cannot substantiate from this mailbox?
  * is a payment, banking-detail change, or purchase being requested?
  * is out-of-band verification being discouraged (secrecy, "I'm in a meeting",
    "don't call me", "handle this discreetly")?
  * is a real thread being hijacked, or a near-identical vendor domain used?
  * is the first message a low-content probe ("are you at your desk?")?

Ordinary internal business mail about invoices is common and legitimate. The
combination of asserted authority + financial action + discouraged verification
is what distinguishes fraud.

Return JSON: score (0-1 BEC/impersonation likelihood), confidence, verdict (BEC
or CLEAN), reasons, observed_techniques."""

# Short, low-content opener used to test whether the target will engage.
# The probe usually follows a greeting and the target's first name, so it is
# matched within the opening of the message rather than anchored to position 0.
PROBE_RE = re.compile(
    r"(are you (at your desk|available|around|free|there)|quick (question|favou?r|task)|need (a )?(quick )?favou?r)",
    re.IGNORECASE,
)
PROBE_WINDOW = 160


class BecAgent(DetectionAgent):
    threat_class = ThreatClass.BEC
    escalation_action = Action.HIGH_RISK_REVIEW
    assert_threshold = 0.55

    @property
    def agent_name(self) -> str:
        return "bec_agent"

    @property
    def instructions(self) -> str:
        return INSTRUCTIONS

    def llm_tools(self) -> tuple[FunctionTool, ...]:
        return (tool(check_domain_tool, name="check_domain"), tool(check_lookalike_tool, name="check_lookalike_domain"))

    def gather_evidence(self, email: Email) -> Evidence:
        evidence = Evidence()

        headers, tc = timed_tool("analyze_email_headers", analyze_email_headers, email)
        evidence.tool_calls.append(tc)
        features, tc = timed_tool("analyze_text_features", analyze_text_features, email.subject, email.body, email.body_html)
        evidence.tool_calls.append(tc)
        sender_domain, tc = timed_tool("check_domain", check_domain, email.sender.domain)
        evidence.tool_calls.append(tc)

        display = headers["display_name_analysis"]
        body = email.body.strip()
        internal_domains = set(email.org_context.get("internal_domains", []))
        known_vendors = set(email.org_context.get("known_vendor_domains", []))
        executives = {name.lower() for name in email.org_context.get("executives", [])}

        # --- authority claim ------------------------------------------------ #
        authority_hit = False
        if display["claims_executive_title"] and display["freemail_sender"]:
            authority_hit = True
            evidence.add("executive_impersonation_freemail",
                         f"Executive authority claimed from a consumer mailbox ({email.sender.domain})", 0.70, Severity.CRITICAL)
        elif display["claims_executive_title"] and internal_domains and registrable_domain(email.sender.domain) not in internal_domains:
            authority_hit = True
            evidence.add("executive_impersonation_external",
                         f"Executive title claimed from external domain {email.sender.domain}", 0.65, Severity.CRITICAL)
        if display["claims_department"] and display["freemail_sender"]:
            authority_hit = True
            evidence.add("department_impersonation", f"Internal department claimed from consumer mailbox {email.sender.domain}", 0.55, Severity.HIGH)

        display_lower = (email.sender.display_name or "").lower()
        if executives and any(exec_name in display_lower for exec_name in executives):
            if internal_domains and registrable_domain(email.sender.domain) not in internal_domains:
                authority_hit = True
                evidence.add("named_executive_from_external_domain",
                             f"Display name matches a known executive but the sender is external ({email.sender.domain})",
                             0.75, Severity.CRITICAL)

        # --- identity infrastructure ---------------------------------------- #
        protected = list(internal_domains) + list(email.org_context.get("protected_domains", []))
        org_look = check_protected_domains(email.sender.domain, protected)
        if org_look["lookalike_domain"]:
            authority_hit = True
            evidence.add("org_domain_lookalike",
                         f"Sender domain {email.sender.domain} imitates the organisation's own domain "
                         f"{org_look['similar_to']} ({org_look['technique']})", 0.80, Severity.CRITICAL)
        if sender_domain["lookalike_domain"]:
            authority_hit = True
            evidence.add("lookalike_sender_domain",
                         f"Sender domain imitates {sender_domain['similar_to']} ({sender_domain['technique']})", 0.70, Severity.CRITICAL)
        for vendor in known_vendors:
            look = detect_lookalike_domain(email.sender.domain, {vendor: vendor})
            if look["lookalike_domain"]:
                authority_hit = True
                evidence.add("vendor_lookalike_domain",
                             f"Sender domain {email.sender.domain} imitates known vendor {vendor}", 0.80, Severity.CRITICAL)
        if sender_domain.get("first_seen_days") is not None and sender_domain["first_seen_days"] < 45 and sender_domain["reputation"] != "GOOD":
            evidence.add("recently_registered_sender_domain",
                         f"Sender domain first observed {sender_domain['first_seen_days']} days ago", 0.45, Severity.HIGH)
        if headers["reply_to_mismatch"]:
            weight = 0.40 if headers["reply_to_freemail"] else 0.25
            evidence.add("reply_redirection",
                         f"Replies are redirected to {headers['reply_to']}, off the sender's domain", weight, Severity.CRITICAL)
        if headers["spoofs_internal_domain"]:
            authority_hit = True
            evidence.add("internal_domain_spoof", "Message claims to be internal but failed authentication", 0.75, Severity.CRITICAL)

        # --- financial request ---------------------------------------------- #
        financial_hit = False
        critical_financial = {"banking_detail_change", "payment_instruction_change", "wire_transfer_request", "gift_card_request", "payroll_diversion", "cryptocurrency_payment_request"}
        for technique in features["financial"]:
            if technique in critical_financial:
                financial_hit = True
                evidence.add(f"financial:{technique}", f"Financial action requested: '{technique}'", 0.55, Severity.CRITICAL)
            elif technique in {"banking_coordinates", "overdue_payment_pressure"}:
                financial_hit = True
                evidence.add(f"financial:{technique}", f"Financial detail present: '{technique}'", 0.30, Severity.HIGH)
            else:
                evidence.add(f"financial:{technique}", f"Financial reference '{technique}'", 0.12, Severity.LOW)

        # --- verification suppression ---------------------------------------- #
        suppression_hit = False
        critical_suppression = {"secrecy_request", "no_verification_instruction", "unreachable_pretext", "channel_restriction", "discretion_pressure"}
        for technique in features["authority_secrecy"]:
            if technique in critical_suppression:
                suppression_hit = True
                evidence.add(f"suppression:{technique}", f"Out-of-band verification discouraged: '{technique}'", 0.45, Severity.CRITICAL)
            else:
                evidence.add(f"suppression:{technique}", f"Social-engineering framing '{technique}'", 0.20, Severity.MEDIUM)
        for technique in features["urgency"]:
            if technique in {"urgency_demand", "artificial_deadline", "priority_framing"}:
                evidence.add(f"urgency:{technique}", f"Time pressure applied: '{technique}'", 0.20, Severity.MEDIUM)

        # --- conversational structure ----------------------------------------- #
        if PROBE_RE.search(body[:PROBE_WINDOW]) and len(body) < 400 and not email.attachments:
            evidence.add("engagement_probe", "Short, contentless opener probing whether the target will engage", 0.45, Severity.HIGH)
        if features["reply_prefix"] and headers["dmarc"]["evaluated"] and headers["dmarc"]["result"] != "pass":
            evidence.add("thread_hijack_pretext", "Reply-prefixed subject on a message that failed authentication (thread-hijack pretext)", 0.45, Severity.HIGH)
        if display["freemail_sender"] and financial_hit:
            evidence.add("freemail_financial_request", "Financial request originating from a consumer mailbox", 0.45, Severity.HIGH)

        # --- correlation ------------------------------------------------------- #
        legs = sum([authority_hit, financial_hit, suppression_hit])
        if legs == 3:
            evidence.add("bec_triad", "Asserted authority + financial action + suppressed verification — classic BEC triad", 0.65, Severity.CRITICAL)
        elif legs == 2:
            evidence.add("bec_dyad", "Two of three BEC legs present (authority / financial action / suppressed verification)", 0.35, Severity.HIGH)

        # --- mitigations --------------------------------------------------------- #
        # A mitigation must never cancel an identity-impersonation finding: an
        # attacker with an authenticated domain of their own is the normal case
        # in BEC, so "it passed DMARC" is not exculpatory when the display name
        # claims someone else.
        identity_impersonation = authority_hit
        internal_authenticated = (
            headers["dmarc"]["result"] == "pass"
            and internal_domains
            and registrable_domain(email.sender.domain) in internal_domains
        )
        if internal_authenticated and not identity_impersonation and not suppression_hit and not headers["reply_to_mismatch"]:
            evidence.mitigate("Authenticated sender on a verified internal domain, with no verification suppression")
            baseline = self.combine_indicators(evidence.indicators)
            evidence.score_override = min(baseline * 0.35, 0.35)
        elif (
            headers["dmarc"]["result"] == "pass"
            and known_vendors
            and registrable_domain(email.sender.domain) in known_vendors
            and not identity_impersonation
            and not suppression_hit
            and not headers["reply_to_mismatch"]
        ):
            evidence.mitigate("Authenticated message from an established vendor domain with no verification suppression")
            baseline = self.combine_indicators(evidence.indicators)
            evidence.score_override = min(baseline * 0.40, 0.40)

        evidence.note(f"Sender: {email.sender} | Reply-To: {headers['reply_to'] or '(none)'}")
        evidence.note(f"Authentication: DMARC={headers['dmarc']['result']}")
        if display["findings"]:
            evidence.note("Identity: " + "; ".join(display["findings"]))
        evidence.note(f"Attachments={len(email.attachments)} URLs={len(email.urls)} (BEC is often payload-free)")
        evidence.note(summarize_for_llm(features))
        return evidence
