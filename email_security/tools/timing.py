"""Tool-call instrumentation helper.

Wrapping every tool invocation in `timed_tool` is what populates
`AgentVerdict.tool_calls`, which is the audit trail an analyst needs to see
*why* a message was actioned — and the same record an OTel span would carry.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from email_security.models.schemas import ToolCall


def timed_tool(name: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, ToolCall]:
    """Run a pure tool, returning (result, ToolCall record). Never raises."""
    started = time.perf_counter()
    record = ToolCall(tool=name, arguments={"args": [_brief(a) for a in args], "kwargs": {k: _brief(v) for k, v in kwargs.items()}})
    try:
        result = func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a tool failure degrades, never aborts
        record.duration_ms = (time.perf_counter() - started) * 1000
        record.error = f"{type(exc).__name__}: {exc}"
        return {}, record
    record.duration_ms = (time.perf_counter() - started) * 1000
    record.result = result if isinstance(result, dict) else {"value": _brief(result)}
    return result, record


def _brief(value: Any, limit: int = 120) -> Any:
    """Keep the audit record readable — arguments can be whole emails."""
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"
