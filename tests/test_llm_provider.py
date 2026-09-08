"""LLM-layer tests.

The Ollama path is exercised against a stub HTTP server that speaks the Ollama
chat API. That validates our provider wiring, structured-output handling and
health check without downloading a multi-gigabyte model into CI.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from email_security.config.settings import get_settings
from email_security.models.heuristic_client import HeuristicChatClient
from email_security.models.llm_provider import (
    FoundryProvider,
    HuggingFaceProvider,
    LLMProviderError,
    OfflineProvider,
    OllamaProvider,
    _extract_json,
    get_llm_provider,
    register_provider,
)
from email_security.models.schemas import LLMAssessment

ASSISTANT_JSON = {"score": 0.87, "confidence": 0.8, "verdict": "PHISHING",
                  "reasons": ["lookalike sender domain", "credential request"],
                  "observed_techniques": ["brand_impersonation"]}


class _StubOllamaHandler(BaseHTTPRequestHandler):
    """Minimal stand-in for `ollama serve`."""

    def log_message(self, *_args):  # silence the default stderr logging
        return

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/tags"):
            self._send({"models": [{"model": "qwen2.5:7b-instruct", "size": 4_700_000_000}]})
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        if not self.path.startswith("/api/chat"):
            self.send_error(404)
            return
        # Echo back that a JSON schema was requested, then answer with one.
        _StubOllamaHandler.last_request = request
        self._send({
            "model": request.get("model", "stub"),
            "created_at": "2025-01-01T00:00:00Z",
            "message": {"role": "assistant", "content": json.dumps(ASSISTANT_JSON)},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 120,
            "eval_count": 45,
        })


@pytest.fixture
def stub_ollama():
    server = HTTPServer(("127.0.0.1", 0), _StubOllamaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


class TestProviderFactory:
    def test_offline_is_always_available(self):
        available, detail = OfflineProvider(get_settings().llm).health_check()
        assert available is True
        assert "no language model" in detail

    def test_unreachable_provider_degrades_to_offline(self):
        settings = get_settings(refresh=True)
        settings.llm.provider = "ollama"
        settings.llm.host = "http://127.0.0.1:1"  # nothing listens here
        provider = get_llm_provider(settings)
        assert provider.name == "offline"
        get_settings(refresh=True)

    def test_unknown_provider_name_degrades_rather_than_raising(self):
        settings = get_settings(refresh=True)
        settings.llm.provider = "does-not-exist"  # type: ignore[assignment]
        assert get_llm_provider(settings).name == "offline"
        get_settings(refresh=True)

    def test_custom_providers_can_be_registered(self):
        class Dummy(OfflineProvider):
            name = "dummy"

        register_provider("dummy", Dummy)
        settings = get_settings(refresh=True)
        settings.llm.provider = "dummy"  # type: ignore[assignment]
        assert get_llm_provider(settings).name == "dummy"
        get_settings(refresh=True)

    def test_foundry_requires_configuration(self):
        settings = get_settings(refresh=True)
        settings.llm.foundry_endpoint = ""
        with pytest.raises(LLMProviderError, match="AZURE_AI_PROJECT_ENDPOINT"):
            FoundryProvider(settings.llm).create_chat_client()

    def test_offline_provider_declares_no_tool_support(self):
        assert OfflineProvider(get_settings().llm).supports_tools is False
        assert OllamaProvider(get_settings().llm).supports_tools is True


class TestOllamaProvider:
    def test_health_check_against_a_live_endpoint(self, stub_ollama):
        settings = get_settings(refresh=True)
        settings.llm.host = stub_ollama
        settings.llm.model = "qwen2.5:7b-instruct"
        available, detail = OllamaProvider(settings.llm).health_check()
        assert available is True
        assert "ollama ok" in detail
        get_settings(refresh=True)

    def test_health_check_reports_a_missing_model(self, stub_ollama):
        settings = get_settings(refresh=True)
        settings.llm.host = stub_ollama
        settings.llm.model = "not-pulled:70b"
        available, detail = OllamaProvider(settings.llm).health_check()
        assert available is False
        assert "not pulled" in detail
        get_settings(refresh=True)

    @pytest.mark.asyncio
    async def test_structured_output_round_trip(self, stub_ollama):
        """An agent built on the real OllamaChatClient must return a typed
        LLMAssessment, and must ask the runtime to constrain the decode."""
        settings = get_settings(refresh=True)
        settings.llm.provider = "ollama"
        settings.llm.host = stub_ollama
        provider = OllamaProvider(settings.llm)
        agent = provider.create_agent(name="phishing_agent", instructions="analyse phishing")
        response = await agent.run("check this", options={"response_format": LLMAssessment})
        assert isinstance(response.value, LLMAssessment)
        assert response.value.score == pytest.approx(0.87)
        assert response.value.verdict == "PHISHING"
        # The JSON schema was pushed down to the runtime as `format`.
        assert "format" in _StubOllamaHandler.last_request
        get_settings(refresh=True)

    @pytest.mark.asyncio
    async def test_detection_agent_uses_a_real_ollama_client(self, stub_ollama, phishing_email):
        """Full agent path: deterministic tools + a real chat client + fusion."""
        import time

        from email_security.agents import PhishingAgent
        from email_security.models.messages import AnalysisRequest

        settings = get_settings(refresh=True)
        settings.llm.provider = "ollama"
        settings.llm.host = stub_ollama
        agent = PhishingAgent("phishing_agent", provider=OllamaProvider(settings.llm), settings=settings)
        verdict = await agent.run_analysis(
            AnalysisRequest(email=phishing_email, correlation_id="c-ollama", started_at=time.perf_counter())
        )
        assert verdict.llm_used is True
        assert verdict.degraded is False
        assert verdict.llm_score == pytest.approx(0.87)
        assert verdict.deterministic_score >= 0.9
        assert verdict.model == "qwen2.5:7b-instruct"
        get_settings(refresh=True)


class TestHeuristicClient:
    @pytest.mark.asyncio
    async def test_echoes_the_evidence_block(self):
        from agent_framework import Agent

        agent = Agent(client=HeuristicChatClient(), instructions="analyse", name="t")
        evidence = json.dumps({"threat_class": "PHISHING", "deterministic_score": 0.82,
                               "indicators": [{"id": "lookalike_domain", "description": "resembles microsoft.com"}]})
        response = await agent.run(f"go\n<EVIDENCE>{evidence}</EVIDENCE>", options={"response_format": LLMAssessment})
        assert response.value.score == pytest.approx(0.82)
        assert response.value.verdict == "PHISHING"
        # An evidence echo is not model confidence, and must not claim to be.
        assert response.value.confidence <= 0.5

    @pytest.mark.asyncio
    async def test_handles_a_missing_evidence_block(self):
        from agent_framework import Agent

        agent = Agent(client=HeuristicChatClient(), instructions="analyse", name="t")
        response = await agent.run("no evidence here", options={"response_format": LLMAssessment})
        assert response.value.score == 0.0
        assert response.value.verdict == "CLEAN"


class TestJsonExtraction:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ('{"a": 1}', {"a": 1}),
            ('Sure!\n```json\n{"a": 1}\n```\ndone', {"a": 1}),
            ('prose {"a": {"b": 2}} trailing', {"a": {"b": 2}}),
            ('{"a": "}not the end{"}', {"a": "}not the end{"}),
        ],
    )
    def test_extracts_the_first_balanced_object(self, text, expected):
        assert json.loads(_extract_json(text)) == expected

    def test_returns_empty_object_when_there_is_no_json(self):
        assert _extract_json("no json at all") == "{}"


class TestHuggingFaceProvider:
    def test_health_check_does_not_raise_when_transformers_is_absent(self):
        available, detail = HuggingFaceProvider(get_settings().llm).health_check()
        assert isinstance(available, bool)
        assert detail
