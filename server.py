#!/usr/bin/env python3
"""Web UI for the email-security multi-agent pipeline.

    .venv/bin/python server.py          →  http://127.0.0.1:8800

This serves a single-page inspector that runs the REAL workflow. Nothing here
re-implements detection in JavaScript: the browser posts an email, the server
runs `workflow.run(stream=True)`, and every Agent Framework `WorkflowEvent` is
forwarded to the page over Server-Sent Events as it happens. What you see
animate is the actual execution — including the superstep boundaries that prove
the five detection agents run concurrently rather than in sequence.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from email_security.agents import AGENT_REGISTRY
from email_security.config.settings import get_settings
from email_security.evaluation.dataset import load_corpus
from email_security.models.schemas import AgentVerdict, Decision, Email
from email_security.observability import configure_logging, get_logger
from email_security.orchestration import IngestionExecutor, PipelinePool
from email_security.policy import build_rules

WEB_DIR = Path(__file__).parent / "web"
SAMPLE_DIR = Path(__file__).parent / "data" / "samples"

settings = get_settings()
configure_logging(settings.observability.log_level, settings.observability.log_format)
logger = get_logger("server")

app = FastAPI(title="Email Security Multi-Agent Inspector", docs_url="/api/docs")

# One pool shared by all requests: a Workflow instance cannot run concurrently,
# so browser tabs are served by separate pipelines rather than queued.
_pool: PipelinePool | None = None


def pool() -> PipelinePool:
    global _pool
    if _pool is None:
        _pool = PipelinePool(size=4)
    return _pool


# --------------------------------------------------------------------------- #
# Static + metadata
# --------------------------------------------------------------------------- #


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/meta")
async def meta() -> dict[str, Any]:
    """Everything the UI needs to render the graph and the policy table."""
    provider = pool().provider
    available, detail = provider.health_check()
    thresholds = settings.policy
    return {
        "provider": {
            "name": provider.name,
            "model": provider.model_name,
            "available": available,
            "detail": detail,
            "is_stub": provider.name == "offline",
        },
        "agents": [
            {
                "id": name,
                "threat_class": str(cls.threat_class),
                "escalation_action": str(cls.escalation_action),
                "assert_threshold": cls.assert_threshold,
            }
            for name, cls in AGENT_REGISTRY.items()
        ],
        "fusion": {
            "llm_weight": settings.agents.llm_weight,
            "deterministic_floor_ratio": settings.agents.deterministic_floor_ratio,
            "timeout_seconds": settings.agents.timeout_seconds,
        },
        "policy": {
            "rules": [{"id": r.id, "description": r.description, "action": str(r.action)} for r in build_rules()],
            "thresholds": {
                "malware_quarantine": thresholds.malware_quarantine,
                "phishing_quarantine": thresholds.phishing_quarantine,
                "bec_review": thresholds.bec_review,
                "spam_junk": thresholds.spam_junk,
                "impersonation_review": thresholds.impersonation_review,
                "suspicious_floor": thresholds.suspicious_floor,
                "composite_quarantine": thresholds.composite_quarantine,
                "min_coverage_for_clean": thresholds.min_coverage_for_clean,
            },
        },
        "mermaid": pool().visualize(),
    }


@app.get("/api/samples")
async def samples() -> list[dict[str, Any]]:
    """Labelled corpus messages plus the held-out sample files."""
    items: list[dict[str, Any]] = []
    for entry in load_corpus():
        items.append({
            "id": entry.email.message_id,
            "group": "corpus",
            "subject": entry.email.subject,
            "sender": str(entry.email.sender),
            "label": str(entry.label),
            "expected_action": str(entry.expected_action),
            "difficulty": entry.difficulty,
            "notes": entry.notes,
        })
    for path in sorted(SAMPLE_DIR.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items.append({
            "id": payload.get("message_id", path.stem),
            "group": "held-out" if path.parent.name == "unseen" else "sample",
            "subject": payload.get("subject", ""),
            "sender": payload.get("sender", ""),
            "label": None,
            "expected_action": None,
            "difficulty": "",
            "notes": path.name,
            "path": str(path.relative_to(Path(__file__).parent)),
        })
    return items


@app.get("/api/samples/{sample_id}")
async def sample(sample_id: str) -> dict[str, Any]:
    for entry in load_corpus():
        if entry.email.message_id == sample_id:
            return json.loads(entry.email.model_dump_json(exclude_defaults=False, exclude_none=True))
    for path in sorted(SAMPLE_DIR.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if payload.get("message_id") == sample_id or path.stem == sample_id:
            return payload
    raise HTTPException(status_code=404, detail=f"unknown sample: {sample_id}")


# --------------------------------------------------------------------------- #
# Analysis stream
# --------------------------------------------------------------------------- #


class AnalyzeRequest(BaseModel):
    email: dict[str, Any] = Field(description="Normalized email payload, or a Microsoft Graph message")
    source: str = Field(default="json", description="json | graph")


def _sse(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"


def _verdicts_in(data: Any) -> list[AgentVerdict]:
    """An executor_completed event carries the list of messages it emitted."""
    items = data if isinstance(data, list) else [data]
    return [item for item in items if isinstance(item, AgentVerdict)]


async def _stream_analysis(email: Email) -> AsyncIterator[str]:
    """Forward every workflow event to the browser as it happens."""
    started = time.perf_counter()

    def elapsed() -> float:
        return round((time.perf_counter() - started) * 1000, 2)

    pipeline = await pool()._free.get()
    try:
        yield _sse("run_started", {
            "at": elapsed(),
            "message_id": email.message_id,
            "subject": email.subject,
            "sender": str(email.sender),
            "urls": email.urls,
            "attachments": [a.filename for a in email.attachments],
            "provider": pipeline.provider.name,
            "model": pipeline.provider.model_name,
        })

        superstep = 0
        decision: Decision | None = None
        async with pipeline._lock:
            async for event in pipeline.workflow.run(email, stream=True):
                kind = event.type
                executor_id = event.executor_id

                if kind == "superstep_started":
                    superstep += 1
                    yield _sse("superstep", {"at": elapsed(), "index": superstep, "phase": "started"})
                elif kind == "superstep_completed":
                    yield _sse("superstep", {"at": elapsed(), "index": superstep, "phase": "completed"})
                elif kind == "executor_invoked":
                    yield _sse("node_started", {"at": elapsed(), "node": executor_id, "superstep": superstep})
                elif kind == "executor_completed":
                    payload: dict[str, Any] = {"at": elapsed(), "node": executor_id, "superstep": superstep}
                    for verdict in _verdicts_in(event.data):
                        payload["verdict"] = json.loads(verdict.model_dump_json())
                    yield _sse("node_completed", payload)
                elif kind == "executor_failed":
                    yield _sse("node_failed", {"at": elapsed(), "node": executor_id, "error": str(event.details or event.data)})
                elif kind == "output" and isinstance(event.data, Decision):
                    decision = event.data
                elif kind == "request_info":
                    yield _sse("awaiting_human", {"at": elapsed(), "node": executor_id})

        if decision is None:
            yield _sse("error", {"at": elapsed(), "message": "workflow produced no Decision"})
            return

        # Recompute the aggregate view the policy engine saw, so the UI can show
        # the score dictionary and coverage alongside the rules that fired.
        scores = {v.agent_name: v.score for v in decision.agent_results}
        yield _sse("decision", {
            "at": elapsed(),
            "decision": json.loads(decision.model_dump_json()),
            "scores": scores,
            "policy_rules_all": [
                {"id": r.id, "description": r.description, "action": str(r.action),
                 "fired": r.id in decision.policy_rules_fired}
                for r in build_rules()
            ],
        })
        yield _sse("done", {"at": elapsed()})
    except Exception as exc:
        logger.exception("analysis stream failed")
        yield _sse("error", {"at": elapsed(), "message": f"{type(exc).__name__}: {exc}"})
    finally:
        pool()._free.put_nowait(pipeline)


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> StreamingResponse:
    try:
        email = IngestionExecutor.normalize(request.email, source=request.source)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"could not parse email: {exc}") from exc

    return StreamingResponse(
        _stream_analysis(email),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.get("/api/health")
async def health() -> dict[str, Any]:
    available, detail = pool().provider.health_check()
    return {"status": "ok", "provider": pool().provider.name, "available": available, "detail": detail}


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Serve the email-security inspector UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8800, help="default 8800 to avoid the common 8000 clash")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    print(f"\n  Email Security Inspector  →  http://{args.host}:{args.port}\n")
    uvicorn.run("server:app" if args.reload else app, host=args.host, port=args.port, reload=args.reload, log_level="warning")


if __name__ == "__main__":
    main()
