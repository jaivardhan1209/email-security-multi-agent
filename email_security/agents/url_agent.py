"""URL Analysis Agent (§3E).

WHY IT IS A SEPARATE AGENT: URL reputation is the one signal that is equally
relevant to phishing, malware delivery and fraud, and it is the signal most
likely to be replaced by a real external service (Defender SafeLinks, MDTI).
Isolating it means that swap touches one file.

It runs concurrently with the other detection agents; the phishing and malware
agents call the same URL *tools* directly rather than waiting on this agent's
verdict, so no serialisation is introduced by the extra node.
"""

from __future__ import annotations

from agent_framework import FunctionTool, tool

from email_security.agents.base import DetectionAgent, Evidence
from email_security.models.schemas import Action, Email, Severity, ThreatClass
from email_security.tools.agent_tools import check_domain as check_domain_tool
from email_security.tools.agent_tools import check_url as check_url_tool
from email_security.tools.timing import timed_tool
from email_security.tools.url_tools import analyze_urls, extract_anchor_mismatches, extract_urls

INSTRUCTIONS = """You are a URL and web-infrastructure analyst inside a defensive email security system.

You assess the links in a message: where they really go, whether the destination
is impersonating a brand, and whether the link is constructed to deceive
(obfuscation, open redirects, encoded destinations, display-vs-destination
mismatch, executable payload paths).

You never fetch, resolve or visit a URL. You reason only over the static
analysis supplied to you.

A link to a well-known, correctly-spelled domain over HTTPS is normal and should
not raise the score. Score on deception and destination risk, not on link count.

Return JSON: score (0-1 URL-borne risk), confidence, verdict, reasons,
observed_techniques."""

# Indicators that alone justify treating a link as hostile.
CRITICAL_URL_INDICATORS = {
    "known_malicious_domain": (0.90, "Link resolves to a domain with a malicious reputation"),
    "lookalike_domain": (0.75, "Link host impersonates a known brand"),
    "punycode_host": (0.70, "Link host uses punycode (IDN homograph attack)"),
    "userinfo_obfuscation": (0.70, "Link uses userinfo@host to disguise the real destination"),
    "ip_address_host": (0.60, "Link points at a bare IP address instead of a hostname"),
    "executable_download_path": (0.75, "Link path downloads an executable file"),
    "base64_encoded_destination": (0.65, "Real destination is base64-encoded inside a parameter"),
    "open_redirect_parameter": (0.55, "Link abuses an open redirector"),
    "prefilled_victim_identity": (0.55, "Link pre-fills the recipient's address (credential-harvest kit)"),
}
MODERATE_URL_INDICATORS = {
    "suspicious_tld": (0.30, "Link uses a top-level domain commonly abused for abuse"),
    "credential_themed_path": (0.25, "Link path is credential/verification themed"),
    "url_shortener": (0.30, "Link is behind a URL shortener that hides the destination"),
    "archive_download_path": (0.35, "Link downloads an archive file"),
    "cleartext_http": (0.20, "Link uses unencrypted HTTP"),
    "non_standard_port": (0.30, "Link uses a non-standard port"),
    "excessive_subdomains": (0.20, "Link host has an unusually deep subdomain chain"),
    "percent_encoding_obfuscation": (0.25, "Link is percent-encoded to obscure its content"),
    "excessive_url_length": (0.15, "Link is abnormally long"),
}


class UrlAgent(DetectionAgent):
    threat_class = ThreatClass.PHISHING
    escalation_action = Action.QUARANTINE
    assert_threshold = 0.60

    @property
    def agent_name(self) -> str:
        return "url_agent"

    @property
    def instructions(self) -> str:
        return INSTRUCTIONS

    def llm_tools(self) -> tuple[FunctionTool, ...]:
        return (tool(check_url_tool, name="check_url"), tool(check_domain_tool, name="check_domain"))

    def gather_evidence(self, email: Email) -> Evidence:
        evidence = Evidence()

        urls = list(email.urls)
        if not urls:
            extracted, tc = timed_tool("extract_urls", extract_urls, email.body_text, email.body_html)
            evidence.tool_calls.append(tc)
            urls = extracted or []

        report, tc = timed_tool("analyze_urls", analyze_urls, urls)
        evidence.tool_calls.append(tc)
        mismatches, tc = timed_tool("extract_anchor_mismatches", extract_anchor_mismatches, email.body_html)
        evidence.tool_calls.append(tc)

        if not urls:
            evidence.note("No URLs present in the message")
            evidence.mitigate("Message contains no links")
            return evidence

        evidence.note(f"{len(urls)} URL(s) across domains: {', '.join(report.get('distinct_domains', [])[:8])}")

        seen: set[str] = set()
        for url_report in report.get("reports", []):
            host = url_report.get("host", "")
            for indicator in url_report.get("indicators", []):
                key = indicator.split(":")[0]
                if (key, host) in seen:
                    continue
                seen.add((key, host))
                if key in CRITICAL_URL_INDICATORS:
                    weight, description = CRITICAL_URL_INDICATORS[key]
                    evidence.add(f"url:{key}", f"{description}: {host}", weight, Severity.CRITICAL if weight >= 0.7 else Severity.HIGH,
                                 url=url_report.get("url"))
                elif key in MODERATE_URL_INDICATORS:
                    weight, description = MODERATE_URL_INDICATORS[key]
                    evidence.add(f"url:{key}", f"{description}: {host}", weight, Severity.MEDIUM, url=url_report.get("url"))

            domain_info = url_report.get("domain_analysis", {})
            if domain_info.get("similar_to"):
                evidence.note(
                    f"{host} resembles {domain_info['similar_to']} ({domain_info.get('technique')})"
                )
            age = domain_info.get("first_seen_days")
            if age is not None and age < 30 and domain_info.get("reputation") != "GOOD":
                evidence.add("url:newly_registered_domain", f"Link host {host} was first observed {age} days ago", 0.45, Severity.HIGH)

        for mismatch in mismatches or []:
            evidence.add(
                "url:display_destination_mismatch",
                f"Link text shows '{mismatch['display_domain']}' but points to '{mismatch['href_domain']}'",
                0.70,
                Severity.CRITICAL,
                **mismatch,
            )

        if report.get("highest_risk") == "LOW" and not evidence.indicators:
            evidence.mitigate("All links resolve to known-good domains over HTTPS")

        evidence.note(f"Highest URL risk: {report.get('highest_risk')}")
        if report.get("malicious"):
            evidence.note(f"High-risk URLs: {', '.join(report['malicious'][:5])}")
        return evidence
