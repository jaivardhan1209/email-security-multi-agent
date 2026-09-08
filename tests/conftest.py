"""Shared fixtures. Tests never touch the network or a model runtime."""

from __future__ import annotations

import pytest

from email_security.config.settings import Settings, get_settings
from email_security.models.schemas import Attachment, Email

pytest_plugins = ("pytest_asyncio",)


@pytest.fixture
def settings() -> Settings:
    return get_settings(refresh=True)


def make_email(**overrides) -> Email:
    """A benign, authenticated baseline message. Tests mutate one thing at a time."""
    base = {
        "message_id": "test-001",
        "sender": '"Priya Nandan" <priya.nandan@contoso.com>',
        "recipients": ["alex.morgan@contoso.com"],
        "subject": "Weekly sync notes",
        "body_text": "Hi Alex, notes from today's sync are in the usual folder. Priya",
        "headers": {
            "Authentication-Results": "spf=pass smtp.mailfrom=contoso.com; dkim=pass header.d=contoso.com; dmarc=pass (p=reject)"
        },
        "org_context": {"internal_domains": ["contoso.com"], "executives": ["robert chen"],
                        "known_vendor_domains": ["northwind-traders.com"]},
    }
    base.update(overrides)
    return Email.model_validate(base)


@pytest.fixture
def benign_email() -> Email:
    return make_email()


@pytest.fixture
def phishing_email() -> Email:
    return make_email(
        message_id="test-phish",
        sender='"Microsoft Account Team" <security@micros0ft-login.com>',
        subject="Action required: verify your account",
        body_text=(
            "Dear Customer, we detected unusual sign-in activity. Verify your account within 24 hours "
            "or your account will be suspended. https://micros0ft-login.com/verify?email=alex.morgan@contoso.com"
        ),
        urls=["https://micros0ft-login.com/verify?email=alex.morgan@contoso.com"],
        headers={"Authentication-Results": "spf=fail smtp.mailfrom=micros0ft-login.com; dkim=none; dmarc=fail (p=reject)"},
    )


@pytest.fixture
def malware_email() -> Email:
    return make_email(
        message_id="test-mal",
        sender='"Accounts" <billing@invoice-portal-secure.click>',
        subject="Overdue invoice",
        body_text="Please open the attached invoice.",
        attachments=[Attachment(filename="Invoice_88213.pdf.exe", content_type="application/pdf", size_bytes=486912)],
        headers={"Authentication-Results": "spf=fail; dkim=none; dmarc=fail (p=reject)"},
    )


@pytest.fixture
def bec_email() -> Email:
    return make_email(
        message_id="test-bec",
        sender='"Robert Chen (CEO)" <ceo.robert.chen@outlook.com>',
        reply_to="ceo.robert.chen@outlook.com",
        subject="Urgent wire transfer",
        body_text=(
            "Alex, I need a wire transfer of $148,500.00 to the escrow account today. "
            "Please update the bank details to the account below. Keep this confidential, "
            "I am travelling and cannot take calls."
        ),
        headers={"Authentication-Results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.d=outlook.com; dmarc=pass (p=none)"},
    )
