"""Structured logging + per-message trace collection (§10, §15).

Every analysis carries a `correlation_id`. Each stage emits a trace record with
the fields Microsoft Foundry / OpenTelemetry expect, so swapping this module for
an OTel exporter later is a drop-in change rather than a rewrite.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")


def new_correlation_id() -> str:
    return f"corr-{uuid.uuid4().hex[:12]}"


def set_correlation_id(value: str) -> None:
    _correlation_id.set(value)


def get_correlation_id() -> str:
    return _correlation_id.get()


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line — machine-parsable by design."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": get_correlation_id(),
            "message": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{datetime.now(UTC).strftime('%H:%M:%S')} {record.levelname:<7} [{get_correlation_id()}] {record.getMessage()}"
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict) and extra:
            base += "  " + " ".join(f"{k}={v}" for k, v in extra.items())
        return base


_configured = False


def configure_logging(level: str = "INFO", fmt: str = "json", stream: Any = None) -> None:
    global _configured
    root = logging.getLogger("email_security")
    root.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    if not _configured:
        configure_logging()
    return logging.getLogger(f"email_security.{name}")


def log_event(logger: logging.Logger, message: str, level: int = logging.INFO, **fields: Any) -> None:
    """Log with structured fields attached (never string-interpolated)."""
    logger.log(level, message, extra={"fields": fields})


# --------------------------------------------------------------------------- #
# Trace collection — the visible EMAIL_RECEIVED -> FINAL_DECISION pipeline (§10)
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class TraceSpan:
    stage: str
    correlation_id: str
    email_id: str
    started_at: float
    ended_at: float | None = None
    duration_ms: float = 0.0
    attributes: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TraceCollector:
    """In-memory span store for one email analysis.

    Production equivalent: an OpenTelemetry tracer whose spans ship to Foundry
    tracing / Application Insights. The recording API is intentionally the same
    shape so the swap is mechanical.
    """

    def __init__(self, correlation_id: str, email_id: str) -> None:
        self.correlation_id = correlation_id
        self.email_id = email_id
        self.spans: list[TraceSpan] = []
        self._logger = get_logger("trace")

    def record(self, stage: str, duration_ms: float = 0.0, error: str | None = None, **attributes: Any) -> None:
        span = TraceSpan(
            stage=stage,
            correlation_id=self.correlation_id,
            email_id=self.email_id,
            started_at=time.time(),
            ended_at=time.time(),
            duration_ms=duration_ms,
            attributes=attributes,
            error=error,
        )
        self.spans.append(span)
        log_event(
            self._logger,
            stage,
            level=logging.ERROR if error else logging.INFO,
            email_id=self.email_id,
            duration_ms=round(duration_ms, 2),
            error=error,
            **attributes,
        )

    @contextmanager
    def span(self, stage: str, **attributes: Any) -> Iterator[TraceSpan]:
        started = time.perf_counter()
        span = TraceSpan(
            stage=stage,
            correlation_id=self.correlation_id,
            email_id=self.email_id,
            started_at=time.time(),
            attributes=attributes,
        )
        try:
            yield span
        except Exception as exc:
            span.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            span.ended_at = time.time()
            span.duration_ms = (time.perf_counter() - started) * 1000
            self.spans.append(span)
            log_event(
                self._logger,
                stage,
                level=logging.ERROR if span.error else logging.INFO,
                email_id=self.email_id,
                duration_ms=round(span.duration_ms, 2),
                error=span.error,
                **span.attributes,
            )

    def as_list(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self.spans]


# --------------------------------------------------------------------------- #
# Trace registry
# --------------------------------------------------------------------------- #

# Workflow messages and shared State may be copied as they cross executor
# boundaries, so a collector passed *by value* on the message would fragment
# into several partial traces. A real tracer is ambient rather than carried, so
# collectors live here and executors resolve them by correlation id.
_TRACES: OrderedDict[str, TraceCollector] = OrderedDict()
_MAX_TRACES = 512


def get_trace(correlation_id: str, email_id: str = "") -> TraceCollector:
    """Return the live collector for this analysis, creating it on first use."""
    collector = _TRACES.get(correlation_id)
    if collector is None:
        collector = TraceCollector(correlation_id, email_id)
        _TRACES[correlation_id] = collector
        while len(_TRACES) > _MAX_TRACES:
            _TRACES.popitem(last=False)  # bound memory; oldest analysis wins eviction
    elif email_id and not collector.email_id:
        collector.email_id = email_id
    return collector


def release_trace(correlation_id: str) -> TraceCollector | None:
    """Drop a completed analysis's collector. Safe to call more than once."""
    return _TRACES.pop(correlation_id, None)
