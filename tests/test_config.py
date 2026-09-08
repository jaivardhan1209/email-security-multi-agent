"""Configuration tests.

Settings are read from the environment at construction time, not at import
time — a distinction that is invisible until you try to change a threshold in a
test or reload configuration in a running service.
"""

from __future__ import annotations

import pytest

from email_security.config.settings import Settings, get_settings


def test_refresh_rereads_the_environment(monkeypatch):
    monkeypatch.setenv("POLICY_PHISHING_QUARANTINE", "0.55")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    settings = get_settings(refresh=True)
    assert settings.policy.phishing_quarantine == pytest.approx(0.55)
    assert settings.llm.provider == "ollama"
    monkeypatch.undo()
    restored = get_settings(refresh=True)
    assert restored.policy.phishing_quarantine == pytest.approx(0.90)
    assert restored.llm.provider == "offline"


def test_malformed_values_fall_back_rather_than_crashing(monkeypatch):
    monkeypatch.setenv("POLICY_SPAM_JUNK", "not-a-number")
    monkeypatch.setenv("AGENT_RETRIES", "")
    settings = Settings()
    assert settings.policy.spam_junk == pytest.approx(0.85)
    assert settings.agents.retries == 1
    monkeypatch.undo()
    get_settings(refresh=True)


def test_boolean_parsing(monkeypatch):
    for value, expected in (("true", True), ("1", True), ("on", True), ("no", False), ("false", False)):
        monkeypatch.setenv("ENABLE_LLM_ROUTER", value)
        assert Settings().agents.enable_llm_router is expected
    monkeypatch.undo()
    get_settings(refresh=True)


def test_no_secret_is_baked_into_defaults():
    settings = Settings()
    assert settings.llm.foundry_endpoint == ""
    assert settings.llm.foundry_deployment == ""
