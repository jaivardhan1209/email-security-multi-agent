"""Model-facing tool surface (§6 tool calling, §19 MCP).

The functions in the other `tools/` modules take rich Python objects and
injectable dependencies, which is right for internal use but wrong for a tool
schema: a model needs flat, JSON-typed parameters with no injectable arguments.

This module is the adapter. Every function here has a primitive-only signature
and a docstring written for a model to read, and together they form EXACTLY the
surface that would be exposed by an MCP security server:

    MCP Security Server
      ├── check_url
      ├── check_domain
      ├── check_lookalike_domain
      ├── check_file_hash
      └── check_attachment

Because the surface is already isolated here, standing up that MCP server is a
transport change (wrap these five functions in an MCP server, point the agents
at `MCPStdioTool`/`MCPStreamableHTTPTool`) rather than an architectural one.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from email_security.tools.attachment_tools import analyze_attachment_metadata, calculate_file_hash
from email_security.tools.domain_tools import check_domain as _check_domain
from email_security.tools.domain_tools import detect_lookalike_domain as _detect_lookalike
from email_security.tools.threat_intel import get_threat_intel
from email_security.tools.url_tools import check_url as _check_url


def check_url(url: Annotated[str, Field(description="Absolute http(s) URL to assess")]) -> dict[str, Any]:
    """Statically assess a URL for phishing and malware-delivery risk.

    Parses the URL and analyses its host reputation, lookalike/typosquat
    similarity to known brands, obfuscation techniques, redirect abuse and
    payload-bearing paths. The URL is NEVER fetched, resolved or visited.

    Returns risk (HIGH/MEDIUM/LOW/UNKNOWN), reputation, a list of indicator
    names, and the full domain analysis.
    """
    return _check_url(url)


def check_domain(domain: Annotated[str, Field(description="Hostname or domain, e.g. 'micros0ft-login.com'")]) -> dict[str, Any]:
    """Look up a domain's reputation and check whether it imitates a known brand.

    Combines threat-intelligence reputation with structural analysis: homoglyph
    substitution, typosquatting, brand-token grafting, punycode/IDN labels,
    abused top-level domains and domain age.
    """
    return _check_domain(domain)


def check_lookalike_domain(
    domain: Annotated[str, Field(description="Domain to test")],
) -> dict[str, Any]:
    """Determine whether a domain is impersonating a well-known brand domain.

    Returns `lookalike_domain` (bool), the brand it resembles, and the technique
    used (homoglyph_substitution, typosquatting, brand_token_grafting,
    brand_token_in_subdomain).
    """
    return _detect_lookalike(domain)


def check_file_hash(
    sha256: Annotated[str, Field(description="Lowercase hex SHA256 digest of a file")],
) -> dict[str, Any]:
    """Check a SHA256 file hash against known-bad sample intelligence.

    Returns reputation (MALICIOUS / UNKNOWN), risk, categories and notes. No
    file is opened or executed to answer this.
    """
    intel = get_threat_intel().lookup_hash(sha256)
    return {
        "sha256": sha256,
        "reputation": intel.reputation,
        "risk": intel.risk,
        "categories": list(intel.categories),
        "notes": intel.notes,
    }


def check_attachment(
    filename: Annotated[str, Field(description="Attachment filename including extension")],
    content_type: Annotated[str, Field(description="Declared MIME type")] = "application/octet-stream",
    size_bytes: Annotated[int, Field(description="Declared size in bytes")] = 0,
) -> dict[str, Any]:
    """Statically analyse attachment metadata for malware-delivery risk.

    Checks the extension against executable/script/macro/archive classes, looks
    for double extensions and right-to-left-override filename deception, and
    verifies that the declared MIME type is consistent with the extension.

    The file is NEVER opened, extracted or executed.
    """
    from email_security.models.schemas import Attachment

    return analyze_attachment_metadata(
        Attachment(filename=filename, content_type=content_type, size_bytes=size_bytes)
    )


def compute_file_hash(
    filename: Annotated[str, Field(description="Attachment filename")],
    size_bytes: Annotated[int, Field(description="Declared size in bytes")] = 0,
) -> str:
    """Return the SHA256 digest recorded for an attachment in this analysis."""
    return calculate_file_hash(None, filename, size_bytes)


#: The five-function surface referenced by the MCP migration notes.
MCP_TOOL_SURFACE = (check_url, check_domain, check_lookalike_domain, check_file_hash, check_attachment)
