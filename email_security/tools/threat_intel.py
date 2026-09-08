"""Mock threat-intelligence source (§7, §20).

Everything here is *offline and inert*: no network calls, no detonation, no
contact with live infrastructure. The `ThreatIntelSource` protocol is the seam
where Microsoft Defender Threat Intelligence, the MDO URL reputation service or
an MCP threat-intel server would later be plugged in without touching agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Well-known brands that attackers impersonate. In production this comes from
# the tenant's protected-users / protected-domains list plus MDO brand impersonation intel.
KNOWN_BRANDS: dict[str, str] = {
    "microsoft.com": "Microsoft",
    "office.com": "Microsoft",
    "outlook.com": "Microsoft",
    "azure.com": "Microsoft",
    "sharepoint.com": "Microsoft",
    "onedrive.com": "Microsoft",
    "amazon.com": "Amazon",
    "aws.amazon.com": "Amazon",
    "paypal.com": "PayPal",
    "google.com": "Google",
    "apple.com": "Apple",
    "docusign.com": "DocuSign",
    "docusign.net": "DocuSign",  # DocuSign's real sending domain
    "accountprotection.microsoft.com": "Microsoft",
    "dropbox.com": "Dropbox",
    "linkedin.com": "LinkedIn",
    "adobe.com": "Adobe",
    "netflix.com": "Netflix",
    "chase.com": "Chase",
    "wellsfargo.com": "Wells Fargo",
    "fedex.com": "FedEx",
    "ups.com": "UPS",
    "dhl.com": "DHL",
    "zoom.us": "Zoom",
    "slack.com": "Slack",
    "github.com": "GitHub",
    "salesforce.com": "Salesforce",
    "intuit.com": "Intuit",
    "hmrc.gov.uk": "HMRC",
    "irs.gov": "IRS",
}

# TLDs disproportionately abused for phishing / malware distribution.
SUSPICIOUS_TLDS: set[str] = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "cf", "ml", "tk", "ga",
    "work", "fit", "loan", "date", "review", "country", "stream", "download",
    "racing", "party", "science", "men", "kim", "cricket", "rest", "cam", "quest",
    "surf", "monster", "buzz", "icu", "sbs", "cyou", "lol", "makeup", "hair", "skin",
}

# Free / consumer mail providers — legitimate in general, but a strong BEC signal
# when combined with an executive display name.
FREEMAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "gmx.com",
    "mail.com", "proton.me", "protonmail.com", "yandex.com", "icloud.com",
    "live.com", "msn.com", "zoho.com", "tutanota.com", "inbox.lv", "consultant.com",
}

# URL shorteners hide the true destination from both user and static analysis.
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "bl.ink",
}


@dataclass(frozen=True, slots=True)
class DomainIntel:
    reputation: str = "UNKNOWN"       # MALICIOUS | SUSPICIOUS | NEUTRAL | GOOD | UNKNOWN
    risk: str = "UNKNOWN"             # HIGH | MEDIUM | LOW | UNKNOWN
    categories: tuple[str, ...] = ()
    first_seen_days: int | None = None  # domain age proxy; young domains are risky
    notes: str = ""


@runtime_checkable
class ThreatIntelSource(Protocol):
    """Seam for real intel. Implementations must remain side-effect free."""

    def lookup_domain(self, domain: str) -> DomainIntel: ...
    def lookup_hash(self, sha256: str) -> DomainIntel: ...
    def is_known_good(self, domain: str) -> bool: ...


@dataclass(slots=True)
class MockThreatIntel:
    """Static, deterministic intel used by the POC.

    Deliberately small: agents must not depend on the feed being exhaustive —
    detection has to work on structure and language too.
    """

    malicious_domains: dict[str, DomainIntel] = field(
        default_factory=lambda: {
            "micros0ft-login.com": DomainIntel("MALICIOUS", "HIGH", ("phishing", "credential-harvesting"), 4, "Microsoft credential phishing kit"),
            "account-verify-micrsoft.com": DomainIntel("MALICIOUS", "HIGH", ("phishing",), 2, "Typosquat, newly registered"),
            "secure-paypa1.com": DomainIntel("MALICIOUS", "HIGH", ("phishing",), 9, "PayPal typosquat"),
            "amaz0n-billing.net": DomainIntel("MALICIOUS", "HIGH", ("phishing", "invoice-fraud"), 6, "Amazon invoice lure"),
            "docusign-review.top": DomainIntel("MALICIOUS", "HIGH", ("phishing",), 1, "DocuSign lure on abused TLD"),
            "cdn-delivery-files.xyz": DomainIntel("MALICIOUS", "HIGH", ("malware-distribution",), 3, "Payload staging host"),
            "invoice-portal-secure.click": DomainIntel("MALICIOUS", "HIGH", ("phishing", "bec"), 5, "Fake vendor payment portal"),
            "0ffice365-support.com": DomainIntel("MALICIOUS", "HIGH", ("phishing",), 7, "O365 support impersonation"),
            "sharepoint-docs-share.link": DomainIntel("MALICIOUS", "HIGH", ("phishing",), 2, "Fake SharePoint share"),
            "hr-payroll-update.info": DomainIntel("SUSPICIOUS", "MEDIUM", ("payroll-diversion",), 11, "Payroll diversion pattern"),
            "mail-relay-77.ru": DomainIntel("SUSPICIOUS", "MEDIUM", ("bulk-mail",), 40, "High-volume relay"),
        }
    )
    malicious_hashes: dict[str, DomainIntel] = field(
        default_factory=lambda: {
            # Synthetic digests used by the test corpus — no real malware involved.
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": DomainIntel(
                "MALICIOUS", "HIGH", ("trojan-downloader",), None, "Known-bad sample (synthetic)"
            ),
        }
    )
    good_domains: set[str] = field(
        default_factory=lambda: set(KNOWN_BRANDS) | {
            "contoso.com", "fabrikam.com", "northwind-traders.com", "example.com",
            "githubusercontent.com", "mailchimp.com", "substack.com",
        }
    )

    def lookup_domain(self, domain: str) -> DomainIntel:
        domain = (domain or "").lower().strip(".")
        if domain in self.malicious_domains:
            return self.malicious_domains[domain]
        # Match on the registrable parent too (sub.evil.com -> evil.com).
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.malicious_domains:
                return self.malicious_domains[parent]
        if domain in self.good_domains or any(domain.endswith("." + g) for g in self.good_domains):
            return DomainIntel("GOOD", "LOW", ("known-brand",), 5000, "Allow-listed known domain")
        return DomainIntel()

    def lookup_hash(self, sha256: str) -> DomainIntel:
        return self.malicious_hashes.get((sha256 or "").lower(), DomainIntel())

    def is_known_good(self, domain: str) -> bool:
        return self.lookup_domain(domain).reputation == "GOOD"


_default_intel = MockThreatIntel()


def get_threat_intel() -> ThreatIntelSource:
    """Injection point — override in tests or swap for a real feed."""
    return _default_intel
