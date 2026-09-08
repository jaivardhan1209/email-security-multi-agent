"""Content and language feature extraction (§7 support tool).

Deterministic lexical/structural features over subject + body. These features
are what the Spam, Phishing and BEC agents fuse with the LLM's semantic reading.
Keeping them here means all three agents see the *same* evidence, and a
regression in one lexicon is visible everywhere at once.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# --------------------------------------------------------------------------- #
# Lexicons. Each entry is (regex, human-readable technique name).
# --------------------------------------------------------------------------- #

URGENCY_PATTERNS: list[tuple[str, str]] = [
    (r"\b(urgent|immediately|right away|asap|as soon as possible)\b", "urgency_demand"),
    (r"\b(within|in the next)\s+\d+\s*(minutes?|hours?|business days?)\b", "artificial_deadline"),
    (r"\b(expires?|expiring|expired)\s+(today|tomorrow|in\s+\d+)", "expiry_pressure"),
    (r"\b(final|last)\s+(notice|warning|reminder|chance)\b", "final_notice_pressure"),
    (r"\b(action required|immediate action|act now|do not ignore|failure to (respond|comply))\b", "action_required_pressure"),
    (r"\b(account|access|service) will be (suspended|disabled|terminated|closed|deleted)\b", "account_termination_threat"),
    (r"\b(suspend|deactivat|terminat|restrict)(ed|ion|e)?\s+(your\s+)?(account|access|mailbox)\b", "account_termination_threat"),
]

CREDENTIAL_PATTERNS: list[tuple[str, str]] = [
    (r"\b(verify|confirm|validate|re-?enter|update)\s+(your\s+)?(account|identity|password|credentials|login|sign-?in|details)\b", "credential_verification_request"),
    (r"\b(sign|log)\s*-?\s*in\s+(here|now|to (your|the))\b", "login_solicitation"),
    (r"\b(password|passcode)\s+(reset|expir|change|update)", "password_reset_lure"),
    (r"\b(unusual|suspicious|unrecognized)\s+(sign-?in|login|activity|access)\b", "security_alert_lure"),
    (r"\b(multi-?factor|two-?factor|mfa|2fa)\s+(authentication|verification|code)\b", "mfa_theme"),
    (r"\b(re-?authenticate|re-?validate|re-?activate)\s+(your\s+)?(account|mailbox|session)\b", "reauth_lure"),
    (r"\b(your\s+)?(mailbox|storage|quota)\s+(is\s+)?(full|exceeded|almost full)\b", "quota_lure"),
    (r"\b(click|tap|select)\s+(here|the\s+(link|button))\b", "click_here_cta"),
]

FINANCIAL_PATTERNS: list[tuple[str, str]] = [
    (r"\b(wire|bank)\s+transfer\b", "wire_transfer_request"),
    (r"\b(remit|remittance|disburse|payment)\s+(instructions?|details?|advice)\b", "payment_instruction_change"),
    (r"\b(update|change|new|revised|amended)\s+(the\s+)?(bank|banking|account|payment|wire|routing)\s+(details?|information|instructions?|coordinates)\b", "banking_detail_change"),
    (r"\b(invoice|purchase order|po)\s*#?\s*\d", "invoice_reference"),
    (r"\b(outstanding|overdue|past due|unpaid)\s+(invoice|balance|payment|amount)\b", "overdue_payment_pressure"),
    (r"\b(gift cards?|itunes card|steam card|google play card|prepaid card)\b", "gift_card_request"),
    # Split deliberately: marketing copy mentions bitcoin constantly, but only a
    # request to *send* crypto is a fraud signal. Conflating the two turned a
    # crypto-webinar spam into a BEC escalation.
    (r"\b(wallet address|(btc|eth|usdt|bitcoin) address|pay(ment)? in (bitcoin|btc|crypto|usdt)|"
     r"send (the )?(payment|funds|money) (in|via|using) (bitcoin|btc|crypto|usdt))\b", "cryptocurrency_payment_request"),
    (r"\b(crypto|bitcoin|btc|ethereum|usdt)\b", "cryptocurrency_mention"),
    (r"\b(beneficiary|iban|swift|bic|sort code|routing number|account number)\b", "banking_coordinates"),
    (r"\b(payroll|direct deposit)\s+(update|change|information)\b", "payroll_diversion"),
    (r"[$£€]\s?\d{1,3}(,\d{3})+(\.\d{2})?\b", "large_monetary_amount"),
]

AUTHORITY_SECRECY_PATTERNS: list[tuple[str, str]] = [
    (r"\b(keep|hold)\s+(this|it)\s+(confidential|between us|discreet|quiet)\b", "secrecy_request"),
    (r"\b(do not|don'?t)\s+(discuss|tell|mention|share|inform|contact)\b", "no_verification_instruction"),
    (r"\b(i'?m|i am)\s+(currently\s+)?(in a meeting|travelling|traveling|unavailable|on a call|out of office)\b", "unreachable_pretext"),
    (r"\b(can'?t|cannot|unable to)\s+(talk|speak|call|be reached)\b", "channel_restriction"),
    (r"\b(handle|process|complete)\s+this\s+(discreetly|quietly|personally|yourself)\b", "discretion_pressure"),
    (r"\b(are you (at your desk|available|there|free)|quick (task|favou?r|question))\b", "engagement_probe"),
    (r"\b(this is (a\s+)?(priority|time[- ]sensitive)|needs? to be done (today|now|before))\b", "priority_framing"),
    (r"\bsent from my (iphone|ipad|mobile|android)\b", "mobile_signature_pretext"),
]

PROMOTIONAL_PATTERNS: list[tuple[str, str]] = [
    (r"\b(\d{1,3})\s*%\s*(off|discount|savings?)\b", "discount_offer"),
    (r"\b(free|complimentary)\s+(trial|gift|shipping|sample|consultation|bonus)\b", "free_offer"),
    (r"\b(limited time|while supplies last|today only|flash sale|ends (tonight|today|soon))\b", "scarcity_marketing"),
    (r"\b(buy now|shop now|order now|subscribe now|claim (your|now)|get started today)\b", "hard_cta"),
    (r"\b(unsubscribe|opt.?out|manage (your )?preferences)\b", "unsubscribe_footer"),
    (r"\b(guaranteed|risk.?free|no obligation|money.?back)\b", "guarantee_language"),
    (r"\b(winner|you'?ve won|congratulations you|prize|lottery|sweepstake)\b", "prize_lure"),
    (r"\b(work from home|earn \$?\d+|make money|passive income|financial freedom)\b", "get_rich_lure"),
    (r"\b(viagra|cialis|weight loss|male enhancement|cbd|casino|forex signals)\b", "classic_spam_vertical"),
    (r"\b(seo services|backlinks|guest post|increase your (traffic|ranking)|lead generation)\b", "cold_outreach_spam"),
]

_INVISIBLE_CHARS = {"​", "‌", "‍", "⁠", "﻿", "­"}


def _match(patterns: list[tuple[str, str]], text: str) -> list[str]:
    hits: list[str] = []
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(label)
    return sorted(set(hits))


def analyze_text_features(subject: str, body: str, html: str = "") -> dict[str, Any]:
    """Extract structural + lexical features from message content.

    Returns counts and named techniques rather than a score: scoring is the
    agent's job, feature extraction is the tool's.
    """
    text = f"{subject}\n{body}"
    words = re.findall(r"[A-Za-z']+", text)
    letters = [c for c in text if c.isalpha()]
    upper_ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0
    subject_letters = [c for c in subject if c.isalpha()]
    subject_upper_ratio = (sum(1 for c in subject_letters if c.isupper()) / len(subject_letters)) if subject_letters else 0.0

    non_ascii = [c for c in text if ord(c) > 127 and not unicodedata.category(c).startswith("Z")]
    invisible = [c for c in text if c in _INVISIBLE_CHARS]
    # Mixed-script text inside a single word is a homograph/obfuscation signal.
    mixed_script_words = 0
    for word in words[:400]:
        scripts = {unicodedata.name(c, "").split()[0] for c in word if c.isalpha()}
        if len(scripts) > 1:
            mixed_script_words += 1

    html_tricks: list[str] = []
    if html:
        if re.search(r"font-size\s*:\s*0(\.\d+)?(px|pt|em)?", html, re.IGNORECASE):
            html_tricks.append("zero_font_size_text")
        if re.search(r"(display\s*:\s*none|visibility\s*:\s*hidden)", html, re.IGNORECASE):
            html_tricks.append("hidden_content")
        if re.search(r"color\s*:\s*#?(fff(fff)?|white)\b", html, re.IGNORECASE):
            html_tricks.append("white_on_white_text")
        if re.search(r"<form\b", html, re.IGNORECASE):
            html_tricks.append("embedded_form")
        if re.search(r"type\s*=\s*[\"']password[\"']", html, re.IGNORECASE):
            html_tricks.append("password_input_field")
        if re.search(r"<meta[^>]+http-equiv\s*=\s*[\"']refresh", html, re.IGNORECASE):
            html_tricks.append("meta_refresh_redirect")
        if re.search(r"<script\b", html, re.IGNORECASE):
            html_tricks.append("inline_script")
        text_only = re.sub(r"<[^>]+>", "", html)
        images = len(re.findall(r"<img\b", html, re.IGNORECASE))
        if images and len(text_only.strip()) < 200:
            html_tricks.append("image_only_body")

    greeting_generic = bool(re.search(r"\b(dear (customer|user|client|member|sir/?madam|account holder)|valued customer|hello there)\b", text, re.IGNORECASE))
    has_greeting_name = bool(re.search(r"\b(hi|hello|dear)\s+[A-Z][a-z]{2,}\b", text))
    exclamations = text.count("!")

    return {
        "word_count": len(words),
        "subject_length": len(subject),
        "uppercase_ratio": round(upper_ratio, 3),
        "subject_uppercase_ratio": round(subject_upper_ratio, 3),
        "exclamation_count": exclamations,
        "non_ascii_chars": len(non_ascii),
        "invisible_chars": len(invisible),
        "mixed_script_words": mixed_script_words,
        "generic_greeting": greeting_generic,
        "personalised_greeting": has_greeting_name,
        "urgency": _match(URGENCY_PATTERNS, text),
        "credential": _match(CREDENTIAL_PATTERNS, text),
        "financial": _match(FINANCIAL_PATTERNS, text),
        "authority_secrecy": _match(AUTHORITY_SECRECY_PATTERNS, text),
        "promotional": _match(PROMOTIONAL_PATTERNS, text),
        "html_tricks": html_tricks,
        "reply_prefix": bool(re.match(r"\s*(re|fw|fwd)\s*:", subject, re.IGNORECASE)),
    }


def summarize_for_llm(features: dict[str, Any], max_items: int = 6) -> str:
    """Compact the feature dict into prompt-sized evidence lines."""
    parts: list[str] = []
    for key in ("urgency", "credential", "financial", "authority_secrecy", "promotional", "html_tricks"):
        values = features.get(key) or []
        if values:
            parts.append(f"{key}: {', '.join(values[:max_items])}")
    if features.get("generic_greeting"):
        parts.append("greeting: generic (no recipient name)")
    if features.get("invisible_chars"):
        parts.append(f"obfuscation: {features['invisible_chars']} invisible characters")
    if features.get("mixed_script_words"):
        parts.append(f"obfuscation: {features['mixed_script_words']} mixed-script words")
    return "\n".join(parts) if parts else "no notable lexical signals"
