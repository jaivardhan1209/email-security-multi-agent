"""Domain reputation and lookalike-domain tools (§7).

These are *tools*, not agents: pure, deterministic, side-effect-free functions
with typed inputs and JSON-serialisable outputs. They are the ground truth the
LLM reasons over — never the other way round.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from email_security.tools.threat_intel import (
    FREEMAIL_DOMAINS,
    KNOWN_BRANDS,
    SUSPICIOUS_TLDS,
    ThreatIntelSource,
    get_threat_intel,
)

# Characters attackers substitute to build visually similar domains.
HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "|": "l", "!": "i",
}
MULTI_GLYPHS: list[tuple[str, str]] = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def normalize_domain(domain: str) -> str:
    """Lowercase, strip trailing dot / port / leading www."""
    d = (domain or "").strip().lower().rstrip(".")
    d = d.split(":")[0]
    return d[4:] if d.startswith("www.") else d


def registrable_domain(domain: str) -> str:
    """Naive eTLD+1. Handles the common two-part public suffixes we care about."""
    d = normalize_domain(domain)
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    two_part_suffixes = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "co.in", "com.br", "co.za"}
    if ".".join(parts[-2:]) in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def get_tld(domain: str) -> str:
    d = normalize_domain(domain)
    return d.rsplit(".", 1)[-1] if "." in d else ""


@lru_cache(maxsize=4096)
def levenshtein(a: str, b: str) -> int:
    """Edit distance. Cached because brand comparison is a hot loop."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def deglyph(text: str) -> str:
    """Fold homoglyph substitutions so `micros0ft` collapses to `microsoft`."""
    out = "".join(HOMOGLYPHS.get(ch, ch) for ch in text.lower())
    for src, dst in MULTI_GLYPHS:
        out = out.replace(src, dst)
    return out


def _token_variants(token: str) -> set[str]:
    """Every form a host label might take once obfuscation is undone.

    Covers homoglyph substitution ("micros0ft" -> "microsoft") and version-style
    suffixes ("0ffice365" -> "office"), and keeps the raw form so that genuine
    digits are not mangled by folding ("365" would otherwise fold to "e6s").
    """
    if not token:
        return set()
    stripped = re.sub(r"\d+$", "", token)
    return {v for v in {token, deglyph(token), stripped, deglyph(stripped)} if v}


def is_punycode(domain: str) -> bool:
    """IDN homograph attacks arrive on the wire as xn-- labels."""
    return any(label.startswith("xn--") for label in normalize_domain(domain).split("."))


def detect_lookalike_domain(domain: str, brands: dict[str, str] | None = None) -> dict[str, Any]:
    """Decide whether `domain` is impersonating a known brand.

    Three independent techniques, because attackers rotate between them:
      1. homoglyph folding    (micros0ft-login.com  -> microsoft)
      2. edit distance <= 2   (micrsoft.com         -> microsoft.com)
      3. brand-token grafting (microsoft.evil.xyz / microsoft-secure-login.top)
    """
    brands = brands or KNOWN_BRANDS
    d = normalize_domain(domain)
    reg = registrable_domain(d)
    result: dict[str, Any] = {
        "domain": d,
        "registrable_domain": reg,
        "lookalike_domain": False,
        "similar_to": None,
        "brand": None,
        "technique": None,
        "distance": None,
        "punycode": is_punycode(d),
    }
    if not d:
        return result

    if d in brands or reg in brands:
        return result  # It *is* the brand.

    sld = reg.rsplit(".", 1)[0]
    folded_sld = deglyph(sld)
    # Split the whole host into word-like tokens. Matching on *tokens* rather
    # than substrings is what stops "officesupplies-direct.com" being read as an
    # impersonation of office.com: "office" is a substring but not a token.
    # Tokenise both the raw and the homoglyph-folded host: folding recovers
    # "micros0ft" -> "microsoft", but it also mangles genuine digits
    # ("office365" -> "officee6s"), so both forms must be considered.
    tokens: set[str] = set()
    for raw_token in re.split(r"[.\-_]+", d):
        tokens |= _token_variants(raw_token)
    sld_tokens: set[str] = set()
    for raw_token in re.split(r"[.\-_]+", sld):
        sld_tokens |= _token_variants(raw_token)

    best: tuple[int, str, str] | None = None
    for brand_domain, brand_name in brands.items():
        brand_sld = brand_domain.rsplit(".", 1)[0].split(".")[0]
        if len(brand_sld) < 4:
            continue

        # 1. homoglyph fold produces the brand exactly
        if folded_sld == brand_sld and sld != brand_sld:
            result.update(lookalike_domain=True, similar_to=brand_domain, brand=brand_name,
                          technique="homoglyph_substitution", distance=0)
            return result

        # 2. small edit distance on the second-level label
        dist = levenshtein(folded_sld, brand_sld)
        if dist <= max(1, min(2, len(brand_sld) // 4)) and sld != brand_sld:
            if best is None or dist < best[0]:
                best = (dist, brand_domain, brand_name)

        # 3. the brand appears as a standalone token somewhere in the host.
        #    `office365` counts as the `office` token plus a version suffix.
        matched = [t for t in tokens if t == brand_sld]
        if matched:
            in_registrable = any(t in sld_tokens for t in matched)
            result.update(
                lookalike_domain=True, similar_to=brand_domain, brand=brand_name,
                technique="brand_token_grafting" if in_registrable else "brand_token_in_subdomain",
                distance=None,
            )
            return result

    if best is not None:
        result.update(lookalike_domain=True, similar_to=best[1], brand=best[2],
                      technique="typosquatting", distance=best[0])
    return result


def check_domain(domain: str, intel: ThreatIntelSource | None = None) -> dict[str, Any]:
    """Primary domain verdict tool. Combines intel lookup + structural analysis.

    Mirrors the shape a real reputation API returns, so the call site does not
    change when the mock is replaced by Defender TI.
    """
    intel = intel or get_threat_intel()
    d = normalize_domain(domain)
    ti = intel.lookup_domain(d)
    look = detect_lookalike_domain(d)
    tld = get_tld(d)

    risk = ti.risk
    reasons: list[str] = []
    if ti.notes:
        reasons.append(ti.notes)
    if look["lookalike_domain"]:
        reasons.append(f"Resembles {look['similar_to']} via {look['technique']}")
        risk = "HIGH" if risk in {"UNKNOWN", "LOW"} else risk
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Abused top-level domain .{tld}")
        risk = "MEDIUM" if risk in {"UNKNOWN", "LOW"} else risk
    if look["punycode"]:
        reasons.append("Punycode/IDN label present (possible homograph attack)")
        risk = "HIGH"
    if ti.first_seen_days is not None and ti.first_seen_days < 30 and ti.reputation != "GOOD":
        reasons.append(f"Newly observed domain ({ti.first_seen_days} days)")
        risk = "HIGH" if risk != "HIGH" else risk

    return {
        "domain": d,
        "registrable_domain": registrable_domain(d),
        "risk": risk,
        "reputation": ti.reputation,
        "categories": list(ti.categories),
        "first_seen_days": ti.first_seen_days,
        "lookalike_domain": look["lookalike_domain"],
        "similar_to": look["similar_to"],
        "brand": look["brand"],
        "technique": look["technique"],
        "punycode": look["punycode"],
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "tld": tld,
        "freemail": registrable_domain(d) in FREEMAIL_DOMAINS,
        "reasons": reasons,
    }


def domains_related(a: str, b: str) -> bool:
    """True when two domains plausibly belong to the same organisation."""
    ra, rb = registrable_domain(a), registrable_domain(b)
    if not ra or not rb:
        return False
    if ra == rb:
        return True
    brand_a = KNOWN_BRANDS.get(ra)
    brand_b = KNOWN_BRANDS.get(rb)
    return bool(brand_a and brand_a == brand_b)


def check_protected_domains(domain: str, protected: list[str]) -> dict[str, Any]:
    """Check a sender domain against the tenant's OWN protected domains.

    A global brand list cannot contain the customer's domain, yet
    `contoso-secure.net` or `contos0.com` arriving at Contoso is a higher-signal
    impersonation than any brand lookalike. In production this list comes from
    the tenant's accepted domains plus the anti-phishing policy's protected
    domains.
    """
    if not protected:
        return {"lookalike_domain": False, "similar_to": None, "technique": None}
    brand_map = {registrable_domain(p): p for p in protected if p}
    result = detect_lookalike_domain(domain, brand_map)
    if result["lookalike_domain"]:
        result["brand"] = result["similar_to"]
    return result
