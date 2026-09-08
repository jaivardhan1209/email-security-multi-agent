"""Web API tests.

The UI is only worth having if it shows the real pipeline, so these tests assert
that the SSE stream carries genuine workflow events and a real Decision — not a
summary assembled after the fact.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(server.app) as c:
        yield c


def parse_sse(body: str) -> list[tuple[str, dict]]:
    events: list[tuple[str, dict]] = []
    for chunk in body.split("\n\n"):
        name = payload = None
        for line in chunk.splitlines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                payload = json.loads(line[6:])
        if name and payload is not None:
            events.append((name, payload))
    return events


class TestMetadata:
    def test_index_is_served(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "Email Security Inspector" in response.text

    def test_meta_describes_the_live_pipeline(self, client):
        meta = client.get("/api/meta").json()
        assert {a["id"] for a in meta["agents"]} == {
            "spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent"
        }
        assert len(meta["policy"]["rules"]) >= 11
        assert 0 < meta["fusion"]["deterministic_floor_ratio"] <= 1
        # The UI must be able to warn when no real model is running.
        assert "is_stub" in meta["provider"]
        assert "orchestrator --> phishing_agent" in meta["mermaid"]

    def test_samples_include_corpus_and_held_out(self, client):
        samples = client.get("/api/samples").json()
        groups = {s["group"] for s in samples}
        assert "corpus" in groups and "held-out" in groups
        assert any(s["id"] == "phish-001" and s["label"] == "PHISHING" for s in samples)

    def test_sample_round_trips_into_analysis(self, client):
        email = client.get("/api/samples/phish-001").json()
        assert email["subject"]
        assert client.post("/api/analyze", json={"email": email}).status_code == 200

    def test_unknown_sample_is_404(self, client):
        assert client.get("/api/samples/does-not-exist").status_code == 404


class TestAnalysisStream:
    @pytest.fixture(scope="class")
    def phishing_events(self, client) -> list[tuple[str, dict]]:
        email = client.get("/api/samples/phish-001").json()
        response = client.post("/api/analyze", json={"email": email})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        return parse_sse(response.text)

    def test_stream_reports_every_pipeline_node(self, phishing_events):
        started = {p["node"] for name, p in phishing_events if name == "node_started"}
        assert {"ingestion", "orchestrator", "spam_agent", "phishing_agent", "malware_agent",
                "bec_agent", "url_agent", "risk_aggregator", "policy_engine"} <= started

    def test_every_agent_emits_a_real_verdict(self, phishing_events):
        verdicts = [p["verdict"] for name, p in phishing_events
                    if name == "node_completed" and "verdict" in p]
        assert {v["agent_name"] for v in verdicts} == {
            "spam_agent", "phishing_agent", "malware_agent", "bec_agent", "url_agent"
        }
        for verdict in verdicts:
            # The UI draws the fusion bar from these three; all must be present.
            assert "score" in verdict and "deterministic_score" in verdict and "indicators" in verdict

    def test_detection_agents_share_one_superstep(self, phishing_events):
        """The concurrency the UI claims to visualise must actually be there."""
        supersteps = {}
        for name, payload in phishing_events:
            if name == "node_started" and payload["node"].endswith("_agent"):
                supersteps[payload["node"]] = payload["superstep"]
        assert len(supersteps) == 5
        assert len(set(supersteps.values())) == 1, f"agents split across supersteps: {supersteps}"

    def test_decision_carries_the_full_policy_table(self, phishing_events):
        decision_events = [p for name, p in phishing_events if name == "decision"]
        assert len(decision_events) == 1
        payload = decision_events[0]
        decision = payload["decision"]
        assert decision["final_classification"] == "PHISHING"
        assert decision["recommended_action"] == "QUARANTINE"
        fired = [r["id"] for r in payload["policy_rules_all"] if r["fired"]]
        assert "R2_phishing_quarantine" in fired
        # Every rule is shown, fired or not, so the UI can explain what did NOT fire.
        assert len(payload["policy_rules_all"]) >= 11

    def test_stream_terminates_cleanly(self, phishing_events):
        assert phishing_events[-1][0] == "done"
        assert not any(name == "error" for name, _ in phishing_events)

    def test_benign_mail_is_delivered(self, client):
        email = client.get("/api/samples/leg-002").json()
        events = parse_sse(client.post("/api/analyze", json={"email": email}).text)
        decision = next(p["decision"] for name, p in events if name == "decision")
        assert decision["recommended_action"] == "DELIVER"

    def test_graph_source_is_accepted(self, client):
        graph_message = {
            "internetMessageId": "<ui-graph-1@contoso.com>",
            "subject": "Verify your account now",
            "from": {"emailAddress": {"name": "Microsoft Account Team", "address": "security@micros0ft-login.com"}},
            "toRecipients": [{"emailAddress": {"name": "Alex", "address": "alex.morgan@contoso.com"}}],
            "body": {"contentType": "text", "content": "Verify: https://micros0ft-login.com/verify"},
            "internetMessageHeaders": [{"name": "Authentication-Results", "value": "spf=fail; dkim=none; dmarc=fail (p=reject)"}],
        }
        events = parse_sse(client.post("/api/analyze", json={"email": graph_message, "source": "graph"}).text)
        decision = next(p["decision"] for name, p in events if name == "decision")
        assert decision["recommended_action"] == "QUARANTINE"

    def test_malformed_email_is_rejected_with_422(self, client):
        response = client.post("/api/analyze", json={"email": {"sender": {"address": []}}})
        assert response.status_code == 422
        assert "could not parse" in response.json()["detail"]
