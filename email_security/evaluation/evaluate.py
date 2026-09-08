"""Evaluation runner (§13, §19).

Runs the full workflow over the labelled corpus and reports:
  * overall classification accuracy and macro F1
  * per-class precision / recall / F1
  * the binary threat-vs-clean view (FPR, FNR) an administrator tunes against
  * SECURITY-CRITICAL false negatives (phishing / malware / BEC reaching the inbox)
  * per-agent precision/recall and score separation
  * latency distribution and per-agent timing

Usage:
    python -m email_security.evaluation.evaluate
    python -m email_security.evaluation.evaluate --json results.json --concurrency 8
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from email_security.agents import AGENT_REGISTRY
from email_security.evaluation.dataset import corpus_summary, load_corpus
from email_security.evaluation.metrics import (
    BLOCKING_ACTIONS,
    CRITICAL_CLASSES,
    AgentMetrics,
    ClassMetrics,
    EvaluationSummary,
)
from email_security.models.schemas import Decision, LabeledEmail, ThreatClass
from email_security.observability import configure_logging
from email_security.orchestration import PipelinePool

# Which ground-truth labels each agent is supposed to fire on.
AGENT_POSITIVE_LABELS: dict[str, set[ThreatClass]] = {
    "spam_agent": {ThreatClass.SPAM},
    "phishing_agent": {ThreatClass.PHISHING},
    "malware_agent": {ThreatClass.MALWARE},
    "bec_agent": {ThreatClass.BEC},
    # The URL agent supports phishing and malware delivery, so both count.
    "url_agent": {ThreatClass.PHISHING, ThreatClass.MALWARE},
}
AGENT_CLASS: dict[str, ThreatClass] = {
    "spam_agent": ThreatClass.SPAM,
    "phishing_agent": ThreatClass.PHISHING,
    "malware_agent": ThreatClass.MALWARE,
    "bec_agent": ThreatClass.BEC,
    "url_agent": ThreatClass.PHISHING,
}

#: Classification is graded leniently across families that warrant the same
#: response, because "we called impersonation phishing" is not a security
#: failure — delivering it would be. Action correctness is graded separately
#: and strictly.
EQUIVALENT_CLASSES: dict[ThreatClass, set[ThreatClass]] = {
    ThreatClass.IMPERSONATION: {ThreatClass.IMPERSONATION, ThreatClass.PHISHING, ThreatClass.BEC},
    ThreatClass.BEC: {ThreatClass.BEC, ThreatClass.IMPERSONATION},
    ThreatClass.PHISHING: {ThreatClass.PHISHING, ThreatClass.IMPERSONATION},
}


def _class_matches(predicted: ThreatClass, expected: ThreatClass) -> bool:
    return predicted in EQUIVALENT_CLASSES.get(expected, {expected})


async def run_evaluation(
    items: list[LabeledEmail],
    *,
    pool: PipelinePool | None = None,
    concurrency: int = 4,
) -> tuple[EvaluationSummary, dict[str, AgentMetrics], list[dict[str, Any]]]:
    """Analyse every corpus item and accumulate metrics."""
    pool = pool or PipelinePool(size=max(1, concurrency))

    async def analyse(item: LabeledEmail) -> tuple[LabeledEmail, Decision | None, str | None, float]:
        started = time.perf_counter()
        try:
            decision = await pool.analyze(item.email.model_copy(deep=True))
            return item, decision, None, (time.perf_counter() - started) * 1000
        except Exception as exc:  # noqa: BLE001 - a crash is a result too
            return item, None, f"{type(exc).__name__}: {exc}", (time.perf_counter() - started) * 1000

    results = await asyncio.gather(*(analyse(item) for item in items))

    labels = sorted({item.label for item in items} | {ThreatClass.CLEAN, ThreatClass.SUSPICIOUS}, key=str)
    summary = EvaluationSummary(per_class={str(label): ClassMetrics(label=str(label)) for label in labels})
    agent_metrics: dict[str, AgentMetrics] = {
        name: AgentMetrics(agent_name=name, threat_class=AGENT_CLASS.get(name, ThreatClass.SUSPICIOUS),
                           threshold=AGENT_REGISTRY[name].assert_threshold)
        for name in AGENT_REGISTRY
    }
    rows: list[dict[str, Any]] = []

    for item, decision, error, elapsed_ms in results:
        summary.total += 1
        expected_label = item.label
        expected_action = item.expected_action
        summary.per_class[str(expected_label)].support += 1

        if decision is None:
            # A pipeline crash is scored as a miss on the expected class.
            summary.per_class[str(expected_label)].fn += 1
            if expected_label is not ThreatClass.CLEAN:
                summary.threat_fn += 1
                summary.critical_false_negatives.append(
                    {"message_id": item.email.message_id, "label": str(expected_label), "reason": error or "pipeline error"}
                )
            else:
                summary.threat_tn += 1
            rows.append({"message_id": item.email.message_id, "expected": str(expected_label), "error": error})
            continue

        predicted = decision.final_classification
        summary.latencies_ms.append(decision.total_latency_ms or elapsed_ms)
        if any(v.degraded for v in decision.agent_results):
            summary.degraded_runs += 1

        # ---- multi-class scoring ---------------------------------------- #
        if _class_matches(predicted, expected_label):
            summary.correct_class += 1
            summary.per_class[str(expected_label)].tp += 1
        else:
            summary.per_class[str(expected_label)].fn += 1
            if str(predicted) in summary.per_class:
                summary.per_class[str(predicted)].fp += 1

        # ---- action scoring ---------------------------------------------- #
        action_correct = decision.recommended_action == expected_action
        if not action_correct and expected_label is not ThreatClass.CLEAN:
            # Any action at least as strict as expected still protects the user.
            from email_security.policy import ACTION_SEVERITY

            action_correct = ACTION_SEVERITY[decision.recommended_action] >= ACTION_SEVERITY[expected_action]
        if action_correct:
            summary.correct_action += 1

        # ---- binary threat view ------------------------------------------- #
        blocked = decision.recommended_action in BLOCKING_ACTIONS
        is_threat = expected_label is not ThreatClass.CLEAN
        if is_threat and blocked:
            summary.threat_tp += 1
        elif is_threat and not blocked:
            summary.threat_fn += 1
            if expected_label in CRITICAL_CLASSES:
                summary.critical_false_negatives.append({
                    "message_id": item.email.message_id, "label": str(expected_label),
                    "subject": item.email.subject[:70], "predicted": str(predicted),
                    "action": str(decision.recommended_action), "risk_score": f"{decision.risk_score:.3f}",
                    "difficulty": item.difficulty,
                })
        elif not is_threat and blocked:
            summary.threat_fp += 1
            summary.false_positives.append({
                "message_id": item.email.message_id, "subject": item.email.subject[:70],
                "predicted": str(predicted), "action": str(decision.recommended_action),
                "risk_score": f"{decision.risk_score:.3f}", "difficulty": item.difficulty,
                "reason": (decision.reasons[0] if decision.reasons else ""),
            })
        else:
            summary.threat_tn += 1

        # ---- per-agent scoring --------------------------------------------- #
        for verdict in decision.agent_results:
            metrics = agent_metrics.get(verdict.agent_name)
            if metrics is None:
                continue
            metrics.durations_ms.append(verdict.execution_time_ms)
            if verdict.degraded:
                metrics.degraded += 1
            if verdict.errors:
                metrics.errors += 1
            in_class = expected_label in AGENT_POSITIVE_LABELS.get(verdict.agent_name, set())
            if verdict.agent_name == "url_agent" and not item.email.urls:
                # Scoring the URL agent on link-free mail would understate it:
                # a message with no links is outside its speciality entirely.
                continue
            fired = verdict.score >= metrics.threshold
            if in_class:
                metrics.scores_on_positives.append(verdict.score)
                metrics.tp += int(fired)
                metrics.fn += int(not fired)
            else:
                metrics.scores_on_negatives.append(verdict.score)
                # Only clean mail counts as a false positive for an agent: a BEC
                # message scoring on the phishing agent is corroboration, not error.
                if expected_label is ThreatClass.CLEAN:
                    metrics.fp += int(fired)
                    metrics.tn += int(not fired)

        rows.append({
            "message_id": item.email.message_id,
            "difficulty": item.difficulty,
            "expected_label": str(expected_label),
            "predicted_label": str(predicted),
            "expected_action": str(expected_action),
            "action": str(decision.recommended_action),
            "risk_score": round(decision.risk_score, 4),
            "confidence": round(decision.confidence, 4),
            "latency_ms": round(decision.total_latency_ms, 2),
            "rules": decision.policy_rules_fired,
            "scores": {v.agent_name: round(v.score, 3) for v in decision.agent_results},
            "correct_class": _class_matches(predicted, expected_label),
            "correct_action": action_correct,
        })

    return summary, agent_metrics, rows


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def _bar(value: float, width: int = 22) -> str:
    filled = round(value * width)
    return "█" * filled + "·" * (width - filled)


def render_report(
    summary: EvaluationSummary,
    agent_metrics: dict[str, AgentMetrics],
    rows: list[dict[str, Any]],
    provider: Any,
) -> str:
    lines: list[str] = []
    add = lines.append

    add("=" * 78)
    add("EMAIL SECURITY MULTI-AGENT POC — EVALUATION REPORT")
    add("=" * 78)
    add(f"Messages analysed : {summary.total}")
    add(f"LLM provider      : {provider.name}  (model: {provider.model_name})")
    if provider.name == "offline":
        add("                    NOTE: offline stub — no language model ran. These")
        add("                    numbers measure the deterministic tool+rule layer only.")
    add(f"Agents            : {', '.join(sorted(agent_metrics))}")
    add("")
    add("  CAVEAT: the corpus is synthetic and the detectors were tuned against it,")
    add("  so these figures are IN-SAMPLE. Treat them as a regression baseline for")
    add("  refactoring, not as an estimate of production accuracy.")
    add("")

    add("-- FINAL CLASSIFICATION ----------------------------------------------------")
    add(f"  accuracy (class)      {summary.accuracy:6.1%}  {_bar(summary.accuracy)}")
    add(f"  accuracy (action)     {summary.action_accuracy:6.1%}  {_bar(summary.action_accuracy)}")
    add(f"  macro F1              {summary.macro_f1:6.3f}")
    add("")
    add(f"  {'class':<16}{'support':>8}{'prec':>8}{'recall':>8}{'F1':>8}{'TP':>5}{'FP':>5}{'FN':>5}")
    for metrics in summary.per_class.values():
        if not metrics.support and not metrics.fp:
            continue
        add(f"  {metrics.label:<16}{metrics.support:>8}{metrics.precision:>8.3f}"
            f"{metrics.recall:>8.3f}{metrics.f1:>8.3f}{metrics.tp:>5}{metrics.fp:>5}{metrics.fn:>5}")
    add("")

    add("-- THREAT vs CLEAN (what the administrator tunes) --------------------------")
    add(f"  precision             {summary.threat_precision:6.3f}")
    add(f"  recall                {summary.threat_recall:6.3f}")
    add(f"  F1                    {summary.threat_f1:6.3f}")
    add(f"  false positive rate   {summary.false_positive_rate:6.1%}   (clean mail wrongly actioned)")
    add(f"  false negative rate   {summary.false_negative_rate:6.1%}   (threats delivered to the inbox)")
    add(f"  confusion             TP={summary.threat_tp}  FP={summary.threat_fp}  TN={summary.threat_tn}  FN={summary.threat_fn}")
    add("")

    add("-- SECURITY-CRITICAL FALSE NEGATIVES (phishing / malware / BEC) ------------")
    if not summary.critical_false_negatives:
        add("  none — no phishing, malware or BEC message was delivered")
    for miss in summary.critical_false_negatives:
        add(f"  MISS {miss.get('message_id')} [{miss.get('label')}] "
            f"predicted={miss.get('predicted')} action={miss.get('action')} "
            f"risk={miss.get('risk_score')} ({miss.get('difficulty', '')})")
        if miss.get("subject"):
            add(f"       subject: {miss['subject']}")
    add("")

    add("-- FALSE POSITIVES (legitimate mail actioned) ------------------------------")
    if not summary.false_positives:
        add("  none")
    for fp in summary.false_positives:
        add(f"  FP   {fp['message_id']} -> {fp['predicted']}/{fp['action']} risk={fp['risk_score']} ({fp['difficulty']})")
        add(f"       subject: {fp['subject']}")
        if fp.get("reason"):
            add(f"       reason : {fp['reason'][:100]}")
    add("")

    add("-- PER-AGENT PERFORMANCE ---------------------------------------------------")
    add(f"  {'agent':<16}{'prec':>7}{'recall':>8}{'F1':>7}{'in-cls':>8}{'out-cls':>9}{'sep':>7}{'ms':>8}{'degr':>6}")
    for name in sorted(agent_metrics):
        m = agent_metrics[name]
        add(f"  {m.agent_name:<16}{m.precision:>7.3f}{m.recall:>8.3f}{m.f1:>7.3f}"
            f"{m.mean_score_positive:>8.3f}{m.mean_score_negative:>9.3f}{m.separation:>7.3f}"
            f"{m.mean_latency_ms:>8.1f}{m.degraded:>6}")
    add("  in-cls/out-cls = mean score on in-speciality vs out-of-speciality mail;")
    add("  sep = separation. A high separation is what makes a threshold meaningful.")
    add("")

    add("-- LATENCY -----------------------------------------------------------------")
    add(f"  p50 {summary.latency(50):>9.1f} ms    p90 {summary.latency(90):>9.1f} ms    "
        f"p99 {summary.latency(99):>9.1f} ms    max {summary.latency(100):>9.1f} ms")
    add(f"  degraded runs: {summary.degraded_runs}/{summary.total}")
    add("")

    hard = [r for r in rows if r.get("difficulty") in {"hard", "borderline"}]
    correct_hard = sum(1 for r in hard if r.get("correct_class"))
    add("-- DIFFICULTY BREAKDOWN ----------------------------------------------------")
    add(f"  borderline+hard cases: {correct_hard}/{len(hard)} classified correctly")
    for row in hard:
        if not row.get("correct_class"):
            add(f"    x {row['message_id']:<10} expected {row['expected_label']:<14} got {row['predicted_label']:<14} "
                f"action={row['action']}")
    add("=" * 78)
    return "\n".join(lines)


async def main_async(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the email-security multi-agent pipeline")
    parser.add_argument("--corpus", default="data/emails", help="corpus directory")
    parser.add_argument("--categories", nargs="*", help="limit to these corpus files (by stem)")
    parser.add_argument("--concurrency", type=int, default=4, help="messages analysed in parallel")
    parser.add_argument("--json", dest="json_out", help="write full per-message results to this path")
    parser.add_argument("--log-level", default="WARNING")
    parser.add_argument("--log-format", default="text", choices=["json", "text"])
    args = parser.parse_args(argv)

    configure_logging(args.log_level, args.log_format)
    items = load_corpus(args.corpus, args.categories)
    print(f"Loaded {len(items)} labelled messages: {corpus_summary(items)}\n", file=sys.stderr)

    pool = PipelinePool(size=max(1, args.concurrency))
    started = time.perf_counter()
    summary, agent_metrics, rows = await run_evaluation(items, pool=pool, concurrency=args.concurrency)
    wall_ms = (time.perf_counter() - started) * 1000

    print(render_report(summary, agent_metrics, rows, pool.provider))
    print(f"\nWall clock: {wall_ms:.0f} ms for {len(items)} messages at concurrency {args.concurrency}")

    if args.json_out:
        payload = {
            "provider": {"name": pool.provider.name, "model": pool.provider.model_name},
            "summary": {
                "total": summary.total,
                "accuracy": round(summary.accuracy, 4),
                "action_accuracy": round(summary.action_accuracy, 4),
                "macro_f1": round(summary.macro_f1, 4),
                "threat_precision": round(summary.threat_precision, 4),
                "threat_recall": round(summary.threat_recall, 4),
                "threat_f1": round(summary.threat_f1, 4),
                "false_positive_rate": round(summary.false_positive_rate, 4),
                "false_negative_rate": round(summary.false_negative_rate, 4),
                "latency_p50_ms": summary.latency(50),
                "latency_p90_ms": summary.latency(90),
                "critical_false_negatives": summary.critical_false_negatives,
                "false_positives": summary.false_positives,
            },
            "per_class": {k: v.as_dict() for k, v in summary.per_class.items()},
            "per_agent": {k: v.as_dict() for k, v in agent_metrics.items()},
            "messages": rows,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2))
        print(f"Wrote {args.json_out}")

    # Non-zero exit if a security-critical threat was delivered — CI gate.
    return 1 if summary.critical_false_negatives else 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(argv))


if __name__ == "__main__":
    raise SystemExit(main())
