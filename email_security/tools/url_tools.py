"""URL extraction and static analysis (§7).

Strictly offline: URLs are parsed, decoded and scored. Nothing is fetched,
resolved, or detonated (§20).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from email_security.tools.domain_tools import check_domain, normalize_domain, registrable_domain
from email_security.tools.threat_intel import URL_SHORTENERS, ThreatIntelSource, get_threat_intel

URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.IGNORECASE)
HREF_RE = re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")

# Query keys that commonly carry the harvested identity in credential-phish kits.
IDENTITY_PARAMS = {"email", "e", "user", "username", "login", "acct", "account", "id", "upn"}
# Parameters used by open redirectors.
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "target", "dest", "destination", "continue", "r", "u", "goto"}


def extract_urls(text: str, html: str = "") -> list[str]:
    """Collect URLs from plain text and HTML hrefs, de-duplicated, order-stable."""
    found: list[str] = []
    seen: set[str] = set()
    for candidate in URL_RE.findall(text or ""):
        cleaned = candidate.rstrip(".,;:!?")
        if cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)
    for href, _label in HREF_RE.findall(html or ""):
        cleaned = href.strip().rstrip(".,;:!?")
        if cleaned.lower().startswith(("http://", "https://")) and cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)
    return found


def extract_anchor_mismatches(html: str) -> list[dict[str, str]]:
    """Find <a> tags whose visible text is a *different* domain than the href.

    This is the classic display-vs-destination deception and it is one of the
    highest-precision phishing signals available from static analysis.
    """
    mismatches: list[dict[str, str]] = []
    for href, inner in HREF_RE.findall(html or ""):
        label = TAG_RE.sub("", inner).strip()
        label_urls = URL_RE.findall(label)
        label_domain = ""
        if label_urls:
            label_domain = registrable_domain(urlparse(label_urls[0]).hostname or "")
        elif re.fullmatch(r"[\w.-]+\.[a-z]{2,}", label, re.IGNORECASE):
            label_domain = registrable_domain(label)
        if not label_domain:
            continue
        href_domain = registrable_domain(urlparse(href).hostname or "")
        if href_domain and label_domain != href_domain:
            mismatches.append({"display_text": label, "display_domain": label_domain, "href": href, "href_domain": href_domain})
    return mismatches


def _maybe_base64_domain(value: str) -> str | None:
    """Phish kits often base64 the real destination inside a query parameter."""
    candidate = value.strip()
    if len(candidate) < 12 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate):
        return None
    try:
        padded = candidate.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return None
    match = URL_RE.search(decoded)
    return normalize_domain(urlparse(match.group(0)).hostname or "") if match else None


def check_url(url: str, intel: ThreatIntelSource | None = None) -> dict[str, Any]:
    """Static risk assessment of a single URL.

    Returns a flat, JSON-serialisable dict — the same contract a real URL
    reputation service (or MCP `check_url` tool) would expose.
    """
    intel = intel or get_threat_intel()
    result: dict[str, Any] = {
        "url": url,
        "valid": False,
        "scheme": "",
        "host": "",
        "registrable_domain": "",
        "path": "",
        "risk": "UNKNOWN",
        "reputation": "UNKNOWN",
        "indicators": [],
        "domain_analysis": {},
        "redirect_target": None,
        "redirect_target_analysis": {},
    }
    try:
        parsed = urlparse(url)
    except ValueError:
        result["indicators"] = ["unparsable_url"]
        result["risk"] = "MEDIUM"
        return result

    host = normalize_domain(parsed.hostname or "")
    if not parsed.scheme or not host:
        result["indicators"] = ["unparsable_url"]
        result["risk"] = "MEDIUM"
        return result

    indicators: list[str] = []
    result.update(
        valid=True,
        scheme=parsed.scheme.lower(),
        host=host,
        registrable_domain=registrable_domain(host),
        path=parsed.path or "/",
    )

    domain_report = check_domain(host, intel=intel)
    result["domain_analysis"] = domain_report
    result["reputation"] = domain_report["reputation"]
    risk_rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    risk = domain_report["risk"] if domain_report["risk"] in risk_rank else "UNKNOWN"

    def raise_risk(level: str) -> None:
        nonlocal risk
        if risk_rank[level] > risk_rank.get(risk, 0):
            risk = level

    if domain_report["lookalike_domain"]:
        indicators.append("lookalike_domain")
        raise_risk("HIGH")
    if domain_report["punycode"]:
        indicators.append("punycode_host")
        raise_risk("HIGH")
    if domain_report["suspicious_tld"]:
        indicators.append("suspicious_tld")
        raise_risk("MEDIUM")
    if domain_report["reputation"] == "MALICIOUS":
        indicators.append("known_malicious_domain")
        raise_risk("HIGH")

    # IP literal instead of a hostname
    try:
        ipaddress.ip_address(host)
        indicators.append("ip_address_host")
        raise_risk("HIGH")
    except ValueError:
        pass

    if parsed.scheme.lower() == "http":
        indicators.append("cleartext_http")
        raise_risk("MEDIUM")
    if parsed.port and parsed.port not in (80, 443):
        indicators.append("non_standard_port")
        raise_risk("MEDIUM")
    if "@" in (parsed.netloc or ""):
        indicators.append("userinfo_obfuscation")  # https://microsoft.com@evil.tld
        raise_risk("HIGH")
    if registrable_domain(host) in URL_SHORTENERS:
        indicators.append("url_shortener")
        raise_risk("MEDIUM")
    if host.count(".") >= 4:
        indicators.append("excessive_subdomains")
        raise_risk("MEDIUM")
    if len(url) > 180:
        indicators.append("excessive_url_length")
        raise_risk("MEDIUM")
    if unquote(url) != url and "%" in url:
        indicators.append("percent_encoding_obfuscation")
        raise_risk("MEDIUM")
    if re.search(r"\.(exe|scr|js|vbs|hta|jar|ps1|bat|cmd|msi|apk|iso|img|lnk)(\?|$)", parsed.path, re.IGNORECASE):
        indicators.append("executable_download_path")
        raise_risk("HIGH")
    if re.search(r"\.(zip|rar|7z|gz)(\?|$)", parsed.path, re.IGNORECASE):
        indicators.append("archive_download_path")
        raise_risk("MEDIUM")
    if re.search(r"(login|signin|verify|secure|account|update|confirm|auth|mfa|password|unlock)", parsed.path, re.IGNORECASE):
        indicators.append("credential_themed_path")
        raise_risk("MEDIUM")

    params = parse_qs(parsed.query or "")
    for key, values in params.items():
        low = key.lower()
        if low in REDIRECT_PARAMS and any(v.lower().startswith("http") for v in values):
            indicators.append("open_redirect_parameter")
            raise_risk("HIGH")
            # A redirector on a trusted host is only as safe as where it sends
            # you. Analyse the declared target too — still without fetching it.
            for value in values:
                if not value.lower().startswith("http"):
                    continue
                target_host = normalize_domain(urlparse(value).hostname or "")
                if not target_host or target_host == host:
                    continue
                target_report = check_domain(target_host, intel=intel)
                result["redirect_target"] = value
                result["redirect_target_analysis"] = target_report
                if target_report["reputation"] == "MALICIOUS" or target_report["lookalike_domain"]:
                    indicators.append("redirect_to_hostile_destination")
                    raise_risk("HIGH")
        if low in IDENTITY_PARAMS and any("@" in v for v in values):
            indicators.append("prefilled_victim_identity")
            raise_risk("HIGH")
        for value in values:
            hidden = _maybe_base64_domain(value)
            if hidden and hidden != host:
                indicators.append("base64_encoded_destination")
                raise_risk("HIGH")

    if risk == "UNKNOWN":
        risk = "LOW" if domain_report["reputation"] == "GOOD" else "UNKNOWN"

    result["indicators"] = sorted(set(indicators))
    result["risk"] = risk
    return result


def analyze_urls(urls: list[str], intel: ThreatIntelSource | None = None) -> dict[str, Any]:
    """Batch helper returning both per-URL reports and a rolled-up summary."""
    reports = [check_url(u, intel=intel) for u in urls]
    highest = "UNKNOWN"
    order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    for r in reports:
        if order.get(r["risk"], 0) > order.get(highest, 0):
            highest = r["risk"]
    return {
        "count": len(reports),
        "highest_risk": highest,
        "malicious": [r["url"] for r in reports if r["risk"] == "HIGH"],
        "suspicious": [r["url"] for r in reports if r["risk"] == "MEDIUM"],
        "distinct_domains": sorted({r["registrable_domain"] for r in reports if r["registrable_domain"]}),
        "reports": reports,
    }
