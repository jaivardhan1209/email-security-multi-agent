"""Tool-layer tests. These are the facts every agent reasons over, so they are
the tests that must never be allowed to rot."""

from __future__ import annotations

import pytest

from email_security.models.schemas import Attachment
from email_security.tools.attachment_tools import analyze_attachment_metadata, calculate_file_hash, detect_double_extension
from email_security.tools.content_tools import analyze_text_features
from email_security.tools.domain_tools import (
    check_domain,
    check_protected_domains,
    detect_lookalike_domain,
    domains_related,
    levenshtein,
    registrable_domain,
)
from email_security.tools.header_tools import analyze_email_headers, check_dkim, check_dmarc, check_spf
from email_security.tools.url_tools import check_url, extract_anchor_mismatches, extract_urls
from tests.conftest import make_email


class TestDomainTools:
    @pytest.mark.parametrize(
        ("domain", "expected_brand", "technique"),
        [
            ("micros0ft-login.com", "microsoft.com", "brand_token_grafting"),
            ("secure-paypa1.com", "paypal.com", "brand_token_grafting"),
            ("microsoft.com.secure-verify.xyz", "microsoft.com", "brand_token_in_subdomain"),
            ("0ffice365-support.com", "office.com", "brand_token_grafting"),
            ("g00gle-workspace.com", "google.com", "brand_token_grafting"),
        ],
    )
    def test_detects_lookalikes(self, domain, expected_brand, technique):
        result = detect_lookalike_domain(domain)
        assert result["lookalike_domain"] is True
        assert result["similar_to"] == expected_brand
        assert result["technique"] == technique

    @pytest.mark.parametrize(
        "domain",
        [
            "microsoft.com", "outlook.office.com", "github.com", "docusign.net", "netflix.com",
            # Regression: "office" is a substring here but not a standalone token.
            "officesupplies-direct.com",
            "wellnessweekly-digest.com", "growthleads-agency.com", "northwind-traders.com",
        ],
    )
    def test_no_false_lookalikes(self, domain):
        assert detect_lookalike_domain(domain)["lookalike_domain"] is False

    def test_punycode_is_high_risk(self):
        report = check_domain("xn--micosoft-i2a.com")
        assert report["punycode"] is True
        assert report["risk"] == "HIGH"

    def test_protected_domains_catch_tenant_impersonation(self):
        for domain in ("contoso-secure.net", "contos0.com", "contoso.com.co"):
            assert check_protected_domains(domain, ["contoso.com"])["lookalike_domain"] is True
        assert check_protected_domains("contoso.com", ["contoso.com"])["lookalike_domain"] is False
        assert check_protected_domains("fabrikam.com", ["contoso.com"])["lookalike_domain"] is False

    def test_registrable_domain_handles_multipart_suffix(self):
        assert registrable_domain("mail.example.co.uk") == "example.co.uk"
        assert registrable_domain("www.contoso.com") == "contoso.com"

    def test_domains_related_uses_brand_identity(self):
        assert domains_related("outlook.com", "microsoft.com") is True
        assert domains_related("a.contoso.com", "contoso.com") is True
        assert domains_related("contoso.com", "fabrikam.com") is False

    def test_levenshtein(self):
        assert levenshtein("microsoft", "micrsoft") == 1
        assert levenshtein("abc", "abc") == 0


class TestUrlTools:
    def test_flags_known_malicious_host(self):
        report = check_url("https://micros0ft-login.com/verify?email=a@b.com")
        assert report["risk"] == "HIGH"
        assert "known_malicious_domain" in report["indicators"]
        assert "prefilled_victim_identity" in report["indicators"]

    def test_flags_ip_literal_and_executable_path(self):
        report = check_url("http://185.203.117.44/dl/update.exe")
        assert "ip_address_host" in report["indicators"]
        assert "executable_download_path" in report["indicators"]
        assert "cleartext_http" in report["indicators"]

    def test_userinfo_obfuscation(self):
        assert "userinfo_obfuscation" in check_url("https://microsoft.com@evil.top/login")["indicators"]

    def test_open_redirect_target_is_analysed_statically(self):
        report = check_url("https://linkedin.com/comm/redirect?url=https://account-verify-micrsoft.com/login")
        assert "open_redirect_parameter" in report["indicators"]
        assert "redirect_to_hostile_destination" in report["indicators"]
        assert report["redirect_target_analysis"]["reputation"] == "MALICIOUS"

    def test_trusted_url_stays_low(self):
        report = check_url("https://outlook.office.com/mail/inbox")
        assert report["risk"] == "LOW"
        assert report["indicators"] == []

    def test_extract_urls_from_text_and_html(self):
        urls = extract_urls("see https://a.example.com/x.", '<a href="https://b.example.com/y">click</a>')
        assert urls == ["https://a.example.com/x", "https://b.example.com/y"]

    def test_anchor_mismatch_detection(self):
        mismatches = extract_anchor_mismatches('<a href="https://evil.top/x">https://microsoft.com/verify</a>')
        assert mismatches[0]["display_domain"] == "microsoft.com"
        assert mismatches[0]["href_domain"] == "evil.top"

    def test_anchor_without_mismatch_is_silent(self):
        assert extract_anchor_mismatches('<a href="https://microsoft.com/a">https://microsoft.com/a</a>') == []


class TestHeaderTools:
    def test_parses_authentication_results(self):
        email = make_email(headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"})
        assert check_spf(email)["result"] == "fail"
        assert check_dkim(email)["result"] == "none"
        dmarc = check_dmarc(email)
        assert dmarc["result"] == "fail"
        assert dmarc["policy"] == "reject"

    def test_derives_dmarc_when_absent(self):
        email = make_email(headers={"Received-SPF": "pass (contoso.com)"})
        assert check_dmarc(email)["derived"] is True

    def test_display_name_brand_impersonation(self):
        email = make_email(sender='"Microsoft Account Team" <no-reply@micros0ft-login.com>')
        analysis = analyze_email_headers(email)["display_name_analysis"]
        assert analysis["impersonated_brand"] == "Microsoft"
        assert analysis["deceptive"] is True

    def test_genuine_brand_is_not_impersonation(self):
        email = make_email(sender='"Microsoft account team" <noreply@accountprotection.microsoft.com>')
        assert analyze_email_headers(email)["display_name_analysis"]["impersonated_brand"] is None

    def test_reply_to_divergence(self):
        email = make_email(reply_to="attacker@gmail.com")
        headers = analyze_email_headers(email)
        assert headers["reply_to_mismatch"] is True
        assert headers["reply_to_freemail"] is True

    def test_internal_domain_spoof(self):
        email = make_email(headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"})
        assert analyze_email_headers(email)["spoofs_internal_domain"] is True


class TestAttachmentTools:
    def test_double_extension(self):
        assert detect_double_extension("Invoice.pdf.exe") == ".pdf.exe"
        assert detect_double_extension("report.pdf") is None

    def test_executable_is_malicious(self):
        report = analyze_attachment_metadata(Attachment(filename="a.pdf.exe", content_type="application/pdf", size_bytes=1000))
        assert report["verdict"] == "MALICIOUS"

    def test_magic_bytes_contradicting_extension(self):
        report = analyze_attachment_metadata(
            Attachment(filename="invoice.pdf", content_type="application/pdf", size_bytes=5000, content=b"MZ\x90\x00payload")
        )
        assert "content_is_executable_but_extension_is_not" in report["indicators"]
        assert report["verdict"] == "MALICIOUS"

    def test_macro_strings_detected_without_execution(self):
        report = analyze_attachment_metadata(
            Attachment(filename="p.xlsm", content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                       size_bytes=90000, content=b"PK\x03\x04 vbaProject.bin Auto_Open WScript.Shell")
        )
        assert "active_content:auto_open_macro" in report["indicators"]
        assert report["verdict"] == "MALICIOUS"

    def test_clean_pdf_is_benign(self):
        report = analyze_attachment_metadata(
            Attachment(filename="report.pdf", content_type="application/pdf", size_bytes=180000, content=b"%PDF-1.7 hello")
        )
        assert report["verdict"] == "BENIGN"
        assert report["risk_score"] == 0.0

    def test_hash_is_stable(self):
        assert calculate_file_hash(b"abc") == calculate_file_hash(b"abc")
        assert calculate_file_hash(b"abc") != calculate_file_hash(b"abd")


class TestContentTools:
    def test_extracts_named_techniques(self):
        features = analyze_text_features(
            "URGENT: your account will be suspended",
            "Dear Customer, verify your account immediately. Click here.",
            '<input type="password">',
        )
        assert "account_termination_threat" in features["urgency"]
        assert "credential_verification_request" in features["credential"]
        assert "password_input_field" in features["html_tricks"]
        assert features["generic_greeting"] is True

    def test_detects_invisible_character_evasion(self):
        features = analyze_text_features("U​r​g​e​n​t", "hello", "")
        assert features["invisible_chars"] >= 4

    def test_benign_text_is_quiet(self):
        features = analyze_text_features("Weekly sync notes", "Hi Alex, notes are in the folder. Priya", "")
        assert features["urgency"] == []
        assert features["credential"] == []
        assert features["financial"] == []
