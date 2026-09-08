"""Email authentication and header-forensics tools (§7).

Covers SPF / DKIM / DMARC evaluation, display-name deception, Reply-To
divergence and Received-chain anomalies. In production these values are read
from the message's `Authentication-Results` header written by Exchange Online
Protection; the parsing contract here is identical.
"""

from __future__ import annotations

import re
from typing import Any

from email_security.models.schemas import AuthResult, Email
from email_security.tools.domain_tools import (
    check_domain,
    deglyph,
    domains_related,
    normalize_domain,
    registrable_domain,
)
from email_security.tools.threat_intel import FREEMAIL_DOMAINS, KNOWN_BRANDS

_AUTH_TOKEN_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_DOMAIN_RE = re.compile(r"(?:header\.(?:d|from)|smtp\.mailfrom)\s*=\s*([^\s;)]+)", re.IGNORECASE)

# Role words that make a display name authoritative and therefore worth faking.
EXECUTIVE_TITLES = (
    "ceo", "chief executive", "cfo", "chief financial", "coo", "cto", "ciso",
    "president", "vice president", "vp ", "director", "head of", "chairman",
    "managing partner", "general counsel", "founder", "owner", "controller",
)
AUTHORITY_DEPARTMENTS = ("payroll", "accounts payable", "finance", "hr", "it support", "helpdesk", "security team", "billing")


def _parse_auth_results(raw: str) -> dict[str, str]:
    """Parse an RFC 8601 Authentication-Results header into {mechanism: result}."""
    found: dict[str, str] = {}
    for mech, value in _AUTH_TOKEN_RE.findall(raw or ""):
        found.setdefault(mech.lower(), value.lower())
    return found


def _result(value: str | None) -> AuthResult:
    try:
        return AuthResult(str(value).lower())
    except ValueError:
        return AuthResult.NONE


def check_spf(email: Email) -> dict[str, Any]:
    """SPF verdict for the envelope sender."""
    explicit = email.header("Received-SPF") or email.header("X-SPF-Result")
    auth = _parse_auth_results(email.header("Authentication-Results"))
    raw = explicit.split()[0].lower() if explicit else auth.get("spf")
    envelope = email.return_path.address if email.return_path else email.sender.address
    envelope_domain = registrable_domain(envelope.rsplit("@", 1)[-1]) if "@" in envelope else ""
    from_domain = registrable_domain(email.sender.domain)
    return {
        "mechanism": "spf",
        "result": _result(raw).value,
        "envelope_domain": envelope_domain,
        "header_from_domain": from_domain,
        "aligned": bool(envelope_domain) and envelope_domain == from_domain,
        "evaluated": raw is not None,
    }


def check_dkim(email: Email) -> dict[str, Any]:
    """DKIM verdict plus d= alignment against the From: domain."""
    auth = _parse_auth_results(email.header("Authentication-Results"))
    raw = email.header("X-DKIM-Result").lower() or auth.get("dkim")
    signed_domain = ""
    sig = email.header("DKIM-Signature")
    if sig:
        m = re.search(r"\bd\s*=\s*([^;\s]+)", sig)
        if m:
            signed_domain = registrable_domain(m.group(1))
    if not signed_domain:
        m = _HEADER_DOMAIN_RE.search(email.header("Authentication-Results"))
        if m:
            signed_domain = registrable_domain(m.group(1))
    from_domain = registrable_domain(email.sender.domain)
    return {
        "mechanism": "dkim",
        "result": _result(raw).value,
        "signing_domain": signed_domain,
        "header_from_domain": from_domain,
        "aligned": bool(signed_domain) and domains_related(signed_domain, from_domain),
        "evaluated": raw is not None,
    }


def check_dmarc(email: Email) -> dict[str, Any]:
    """DMARC verdict. DMARC only passes if an *aligned* SPF or DKIM passed."""
    auth = _parse_auth_results(email.header("Authentication-Results"))
    raw = email.header("X-DMARC-Result").lower() or auth.get("dmarc")
    spf = check_spf(email)
    dkim = check_dkim(email)
    if raw is None:
        derived = (
            AuthResult.PASS
            if (spf["result"] == "pass" and spf["aligned"]) or (dkim["result"] == "pass" and dkim["aligned"])
            else AuthResult.FAIL
            if spf["evaluated"] or dkim["evaluated"]
            else AuthResult.NONE
        )
    else:
        derived = _result(raw)
    policy = ""
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", email.header("Authentication-Results"), re.IGNORECASE)
    if m:
        policy = m.group(1).lower()
    return {
        "mechanism": "dmarc",
        "result": derived.value,
        "policy": policy,
        "evaluated": raw is not None or spf["evaluated"] or dkim["evaluated"],
        "derived": raw is None,
    }


def detect_display_name_deception(email: Email) -> dict[str, Any]:
    """Does the display name claim an identity the address does not support?

    Three cases matter operationally:
      * display name embeds a brand, address is on an unrelated domain
      * display name embeds an email address different from the real one
      * display name asserts executive authority from a consumer mailbox
    """
    display = (email.sender.display_name or "").strip()
    address = email.sender.address
    domain = email.sender.domain
    folded = deglyph(display.lower())
    findings: list[str] = []
    impersonated_brand: str | None = None

    for brand_domain, brand_name in KNOWN_BRANDS.items():
        token = brand_name.lower()
        if len(token) >= 4 and token in folded and not domains_related(domain, brand_domain):
            impersonated_brand = brand_name
            findings.append(f"Display name claims '{brand_name}' but sender domain is {domain or '(none)'}")
            break

    embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", display)
    if embedded and embedded.group(0).lower() != address:
        findings.append(f"Display name contains a different address ({embedded.group(0)}) than the real sender")

    title = next((t for t in EXECUTIVE_TITLES if t in folded), None)
    dept = next((d for d in AUTHORITY_DEPARTMENTS if d in folded), None)
    freemail = registrable_domain(domain) in FREEMAIL_DOMAINS
    if title and freemail:
        findings.append(f"Executive title '{title.strip()}' asserted from a consumer mail domain ({domain})")
    if dept and freemail:
        findings.append(f"Internal department '{dept}' asserted from a consumer mail domain ({domain})")

    return {
        "display_name": display,
        "sender_address": address,
        "sender_domain": domain,
        "impersonated_brand": impersonated_brand,
        "claims_executive_title": bool(title),
        "claims_department": bool(dept),
        "freemail_sender": freemail,
        "deceptive": bool(findings),
        "findings": findings,
    }


def analyze_email_headers(email: Email) -> dict[str, Any]:
    """Aggregate header forensics — the tool every language agent starts from."""
    spf, dkim, dmarc = check_spf(email), check_dkim(email), check_dmarc(email)
    display = detect_display_name_deception(email)
    sender_domain_report = check_domain(email.sender.domain)

    reply_to = email.reply_to
    reply_to_mismatch = False
    reply_to_freemail = False
    if reply_to and reply_to.address and reply_to.address != email.sender.address:
        reply_to_mismatch = not domains_related(reply_to.domain, email.sender.domain)
        reply_to_freemail = registrable_domain(reply_to.domain) in FREEMAIL_DOMAINS

    return_path_mismatch = False
    if email.return_path and email.return_path.address:
        return_path_mismatch = not domains_related(email.return_path.domain, email.sender.domain)

    received = [v for k, v in email.headers.items() if k.lower() == "received"]
    raw_received = email.header("Received")
    hop_count = len(received) or (raw_received.count("from ") if raw_received else 0)

    recipient_domains = {registrable_domain(r.domain) for r in email.recipients if r.domain}
    internal_domains = set(email.org_context.get("internal_domains", []))
    spoofs_internal = bool(internal_domains) and registrable_domain(email.sender.domain) in internal_domains and dmarc["result"] != "pass"

    bulk_headers = {
        k: v for k, v in email.headers.items()
        if k.lower() in {"list-unsubscribe", "precedence", "x-campaign-id", "x-mailer", "list-id", "feedback-id"}
    }

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "authentication_passed": dmarc["result"] == "pass",
        "display_name_analysis": display,
        "sender_domain_analysis": sender_domain_report,
        "reply_to": reply_to.address if reply_to else None,
        "reply_to_mismatch": reply_to_mismatch,
        "reply_to_freemail": reply_to_freemail,
        "return_path_mismatch": return_path_mismatch,
        "received_hops": hop_count,
        "bulk_mail_headers": bulk_headers,
        "has_unsubscribe": any(k.lower() == "list-unsubscribe" for k in email.headers),
        "recipient_count": len(email.recipients),
        "undisclosed_recipients": len(email.recipients) == 0 or any("undisclosed" in r.address for r in email.recipients),
        "recipient_domains": sorted(recipient_domains),
        "spoofs_internal_domain": spoofs_internal,
        "sender_domain": normalize_domain(email.sender.domain),
    }
