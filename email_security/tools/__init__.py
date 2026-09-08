"""Deterministic security tools.

Every function here is pure, offline and side-effect free — the property that
lets them be exposed later as MCP tools (§19) without any behavioural change.
"""

from email_security.tools.attachment_tools import (
    analyze_attachment_metadata,
    analyze_attachments,
    calculate_file_hash,
)
from email_security.tools.content_tools import analyze_text_features, summarize_for_llm
from email_security.tools.domain_tools import check_domain, detect_lookalike_domain, domains_related
from email_security.tools.header_tools import (
    analyze_email_headers,
    check_dkim,
    check_dmarc,
    check_spf,
    detect_display_name_deception,
)
from email_security.tools.threat_intel import get_threat_intel
from email_security.tools.url_tools import analyze_urls, check_url, extract_anchor_mismatches, extract_urls

__all__ = [
    "analyze_attachment_metadata",
    "analyze_attachments",
    "analyze_email_headers",
    "analyze_text_features",
    "analyze_urls",
    "calculate_file_hash",
    "check_dkim",
    "check_dmarc",
    "check_domain",
    "check_spf",
    "check_url",
    "detect_display_name_deception",
    "detect_lookalike_domain",
    "domains_related",
    "extract_anchor_mismatches",
    "extract_urls",
    "get_threat_intel",
    "summarize_for_llm",
]
