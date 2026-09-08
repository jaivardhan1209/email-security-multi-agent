#!/usr/bin/env python3
"""Command-line entry point for the email-security multi-agent POC.

    python app.py doctor                      # check the model runtime
    python app.py graph                       # print the workflow topology
    python app.py analyze data/samples/x.json # analyze one email file
    python app.py corpus phish-001 --trace    # analyze a corpus message
    python app.py demo                        # three contrasting examples
    python app.py review bec-002              # human-in-the-loop walkthrough
    python app.py evaluate -- --concurrency 8 # full evaluation
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from email_security.config.settings import get_settings
from email_security.evaluation.dataset import load_corpus
from email_security.models.schemas import Action, Decision, Email, HumanReviewResponse
from email_security.observability import configure_logging
from email_security.orchestration import EmailSecurityPipeline, IngestionExecutor

ACTION_STYLE: dict[Action, str] = {
    Action.DELIVER: "\033[32m",           # green
    Action.JUNK: "\033[33m",              # yellow
    Action.HIGH_RISK_REVIEW: "\033[35m",  # magenta
    Action.QUARANTINE: "\033[31m",        # red
    Action.BLOCK: "\033[31;1m",
}
RESET = "\033[0m"


def _colour(text: str, action: Action, enabled: bool) -> str:
    return f"{ACTION_STYLE.get(action, '')}{text}{RESET}" if enabled else text


def render_decision(decision: Decision, email: Email, *, show_trace: bool = False, colour: bool = True) -> str:
    lines: list[str] = []
    add = lines.append
    add("=" * 76)
    add(f"MESSAGE  {decision.message_id}")
    add(f"From     {email.sender}")
    add(f"Subject  {email.subject}")
    add("-" * 76)
    verdict = f"{decision.final_classification}  ->  {decision.recommended_action}"
    add(_colour(f"VERDICT  {verdict}", decision.recommended_action, colour))
    add(f"         risk={decision.risk_score:.3f}  confidence={decision.confidence:.3f}  "
        f"latency={decision.total_latency_ms:.0f} ms")
    if decision.requires_human_review:
        add("         HELD FOR ANALYST REVIEW")
    if decision.fail_safe_applied:
        add("         FAIL-SAFE APPLIED — analysis was incomplete")
    add("")
    add("AGENT SCORES")
    for verdict_item in sorted(decision.agent_results, key=lambda v: v.score, reverse=True):
        bar = "█" * round(verdict_item.score * 20)
        flags = []
        if verdict_item.degraded:
            flags.append("DEGRADED")
        if not verdict_item.llm_used:
            flags.append("no-llm")
        add(f"  {verdict_item.agent_name:<16}{verdict_item.score:5.3f} {bar:<20} "
            f"det={verdict_item.deterministic_score:.2f} "
            f"llm={verdict_item.llm_score if verdict_item.llm_score is not None else '  - '} "
            f"conf={verdict_item.confidence:.2f} {verdict_item.execution_time_ms:6.1f}ms "
            f"{' '.join(flags)}")
    add("")
    add("POLICY")
    add(f"  rules fired: {', '.join(decision.policy_rules_fired) or '(none)'}")
    add("")
    add("REASONS")
    for reason in decision.reasons[:12]:
        add(f"  - {reason}")
    add("")
    add("EVIDENCE (top agents)")
    for verdict_item in sorted(decision.agent_results, key=lambda v: v.score, reverse=True)[:2]:
        if verdict_item.score < 0.2:
            continue
        add(f"  [{verdict_item.agent_name}] tools: {', '.join(dict.fromkeys(verdict_item.tools_called))}")
        for line in verdict_item.evidence[:6]:
            add(f"    · {line}")
    if show_trace:
        add("")
        add("TRACE")
        for span in decision.trace:
            marker = "!" if span.get("error") else " "
            add(f"  {marker} {span['stage']:<28} {span['duration_ms']:8.2f} ms  "
                + " ".join(f"{k}={v}" for k, v in (span.get("attributes") or {}).items() if v not in (None, "", 0)))
    add("=" * 76)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


async def cmd_doctor(args: argparse.Namespace) -> int:
    from email_security.models.llm_provider import (
        FoundryProvider,
        HuggingFaceProvider,
        OfflineProvider,
        OllamaProvider,
        get_llm_provider,
    )

    settings = get_settings()
    print("Configured provider :", settings.llm.provider)
    print("Configured model    :", settings.llm.model)
    print()
    print(f"{'provider':<14}{'available':<12}detail")
    print("-" * 76)
    for cls in (OfflineProvider, OllamaProvider, HuggingFaceProvider, FoundryProvider):
        info = cls(settings.llm).describe()
        print(f"{info['provider']:<14}{info['available']!s:<12}{info['detail']}")
    print()
    active = get_llm_provider(settings)
    print(f"Active after health check: {active.name} ({active.model_name})")
    if active.name == "offline" and settings.llm.provider != "offline":
        print("  -> the configured provider was unreachable; the system degraded to")
        print("     deterministic-only reasoning rather than failing (see §16 fail-safe).")
    if active.name == "offline":
        print("\nTo enable real model reasoning:")
        print("  curl -fsSL https://ollama.com/install.sh | sh")
        print("  ollama pull qwen2.5:7b-instruct")
        print("  LLM_PROVIDER=ollama python app.py demo")
    return 0


async def cmd_graph(args: argparse.Namespace) -> int:
    pipeline = EmailSecurityPipeline()
    print(pipeline.visualize())
    return 0


async def cmd_analyze(args: argparse.Namespace) -> int:
    raw = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")
    payload: Any = json.loads(raw)
    if isinstance(payload, dict) and "email" in payload:
        payload = payload["email"]
    pipeline = EmailSecurityPipeline()
    email = IngestionExecutor.normalize(payload, source=args.source)
    decision = await pipeline.analyze(email)
    if args.json:
        print(decision.model_dump_json(indent=2))
    else:
        print(render_decision(decision, email, show_trace=args.trace, colour=not args.no_colour))
    return 0


async def cmd_corpus(args: argparse.Namespace) -> int:
    items = {item.email.message_id: item for item in load_corpus(args.corpus)}
    if args.message_id not in items:
        print(f"unknown message id. Available: {', '.join(sorted(items))}", file=sys.stderr)
        return 2
    item = items[args.message_id]
    pipeline = EmailSecurityPipeline()
    decision = await pipeline.analyze(item.email)
    if args.json:
        print(decision.model_dump_json(indent=2))
        return 0
    print(render_decision(decision, item.email, show_trace=args.trace, colour=not args.no_colour))
    print(f"GROUND TRUTH: {item.label} / {item.expected_action}   ({item.difficulty})")
    print(f"NOTE        : {item.notes}")
    return 0


async def cmd_demo(args: argparse.Namespace) -> int:
    """Three contrasting messages that exercise different parts of the system."""
    wanted = ["leg-001", "phish-001", "bec-002", "mal-002"]
    items = {item.email.message_id: item for item in load_corpus(args.corpus)}
    pipeline = EmailSecurityPipeline()
    print(f"Provider: {pipeline.provider.name} ({pipeline.provider.model_name})\n")
    for message_id in wanted:
        item = items[message_id]
        decision = await pipeline.analyze(item.email)
        print(render_decision(decision, item.email, show_trace=args.trace, colour=not args.no_colour))
        print(f"GROUND TRUTH: {item.label} / {item.expected_action}\n")
    return 0


async def cmd_review(args: argparse.Namespace) -> int:
    """Demonstrate the blocking human-in-the-loop path (§17).

    Uses `human_review_mode="request_info"`, so the workflow SUSPENDS and emits a
    request. We answer it and the workflow resumes with the analyst's decision.
    """
    items = {item.email.message_id: item for item in load_corpus(args.corpus)}
    item = items.get(args.message_id)
    if item is None:
        print(f"unknown message id: {args.message_id}", file=sys.stderr)
        return 2

    pipeline = EmailSecurityPipeline(human_review_mode="request_info")
    result = await pipeline.workflow.run(item.email)
    requests = result.get_request_info_events()
    if not requests:
        outputs = result.get_outputs()
        print("Workflow completed without requesting review.")
        if outputs:
            print(render_decision(outputs[-1], item.email, colour=not args.no_colour))
        return 0

    event = requests[0]
    review = event.data
    print("WORKFLOW SUSPENDED — analyst input required")
    print(f"  message   : {review.message_id}")
    print(f"  sender    : {review.sender}")
    print(f"  subject   : {review.subject}")
    print(f"  proposed  : {review.proposed_action}  (risk {review.risk_score:.2f})")
    for reason in review.reasons:
        print(f"    - {reason}")
    print()
    choice = args.decision or "QUARANTINE"
    print(f"Analyst responds: {choice}\n")

    response = HumanReviewResponse(decision=Action(choice), analyst=args.analyst, rationale=args.rationale)
    resumed = await pipeline.workflow.run(responses={event.request_id: response})
    outputs = resumed.get_outputs()
    if outputs:
        print(render_decision(outputs[-1], item.email, show_trace=args.trace, colour=not args.no_colour))
    return 0


async def cmd_evaluate(args: argparse.Namespace) -> int:
    from email_security.evaluation.evaluate import main_async

    return await main_async(args.rest)


# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="app.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-level", default="WARNING")
    parser.add_argument("--log-format", default="text", choices=["json", "text"])
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--corpus", default="data/emails")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check which model runtimes are available").set_defaults(func=cmd_doctor)
    sub.add_parser("graph", help="print the workflow topology as Mermaid").set_defaults(func=cmd_graph)

    analyze = sub.add_parser("analyze", help="analyze one email from a JSON file (or - for stdin)")
    analyze.add_argument("path")
    analyze.add_argument("--source", default="json", choices=["json", "graph"], help="payload shape")
    analyze.add_argument("--trace", action="store_true")
    analyze.add_argument("--json", action="store_true", help="emit the raw Decision as JSON")
    analyze.set_defaults(func=cmd_analyze)

    corpus = sub.add_parser("corpus", help="analyze one message from the labelled corpus")
    corpus.add_argument("message_id")
    corpus.add_argument("--trace", action="store_true")
    corpus.add_argument("--json", action="store_true")
    corpus.set_defaults(func=cmd_corpus)

    demo = sub.add_parser("demo", help="run four contrasting example messages")
    demo.add_argument("--trace", action="store_true")
    demo.set_defaults(func=cmd_demo)

    review = sub.add_parser("review", help="walk through the blocking human-in-the-loop path")
    review.add_argument("message_id")
    review.add_argument("--decision", choices=[a.value for a in Action])
    review.add_argument("--analyst", default="soc.analyst@contoso.com")
    review.add_argument("--rationale", default="Confirmed impersonation of a protected user.")
    review.add_argument("--trace", action="store_true")
    review.set_defaults(func=cmd_review)

    evaluate = sub.add_parser("evaluate", help="run the full evaluation harness")
    evaluate.add_argument("rest", nargs=argparse.REMAINDER)
    evaluate.set_defaults(func=cmd_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_format)
    return asyncio.run(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
