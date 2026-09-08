# Architecture: what every component is, and why

This document answers six questions for each component:

1. What does it do?
2. Why is it an **agent** vs an **executor** vs a **tool**?
3. How does it communicate with the rest of the system?
4. Which **Microsoft Agent Framework** concept does it demonstrate?
5. Why is this design right for *email security* specifically?
6. What would change in a production Microsoft Defender implementation?

---

## The vocabulary, first

These five words get used interchangeably in most "multi-agent" write-ups. They are not
interchangeable, and the whole design rests on keeping them apart:

| Term | Definition used here | Deterministic? | Example |
|---|---|---|---|
| **Tool** | A pure function: typed in, JSON out, no side effects, no state | Yes | `check_url()` |
| **LLM** | A text-in/text-out model behind a `BaseChatClient` | No | `qwen2.5:7b-instruct` |
| **Agent** | An LLM plus instructions, tools and a structured output contract | No | `Agent(client, instructions=…)` |
| **Executor** | A typed node in the workflow graph. May *contain* an agent | Its own logic is | `PhishingAgent(Executor)` |
| **Workflow** | The graph: nodes, typed edges, concurrency, state, checkpoints | Yes | `WorkflowBuilder(...).build()` |
| **Orchestrator** | The executor that decides which specialists run and fans out | Yes (by choice) | `OrchestratorExecutor` |
| **Aggregator** | The fan-in executor that merges verdicts into one risk view | Yes | `RiskAggregatorExecutor` |
| **Policy engine** | Pure rules turning scores into an enforceable action | Yes | `PolicyEngine` |

Only three things in this system are non-deterministic, and all three are *inside* detection
agents: the model call, its structured output, and the fusion input it provides. Everything
that touches mail flow is deterministic.

---

## 1. `IngestionExecutor` — the boundary

**What it does.** Turns whatever arrived from the outside world into the canonical `Email`
model: parses addresses, extracts URLs from text and HTML, computes attachment hashes, mints
a correlation ID and opens the trace.

**Agent, executor or tool?** An **executor**. There is no judgement to make here, only
normalization, and normalization must be identical for every message or downstream detection
is comparing apples to oranges.

**Communication.** Accepts `IngestionEnvelope` or a bare `Email`; emits `AnalysisRequest`.

**Agent Framework concept.** The workflow's **start executor**, and multi-handler dispatch:
two `@handler` methods on different input types, routed by type.

**Why right for email security.** This is the seam that makes the ingestion source
swappable. `from_graph_message()` already maps a Microsoft Graph `message` resource onto the
same `Email`; an `.eml` parser or an Exchange transport-agent shim would be a third branch.
Nothing downstream knows or cares where a message came from — which is the property that
makes the local POC and a production tenant deployment the same code.

**In production.** Fed by a Graph change-notification webhook or an Event Hub consumer
rather than a JSON file, and it gains the tenant context (accepted domains, protected users,
mailbox-level policy) that `org_context` stands in for here.

---

## 2. `OrchestratorExecutor` — routing and fan-out

**What it does.** Decides which specialists examine this message, records the reasoning,
publishes the analysis context into workflow **State**, and dispatches.

**Agent, executor or tool?** An **executor**, deliberately — and this is the most important
"no" in the project. It would be easy to make routing an LLM decision. It should not be:

> If an attacker can influence which detectors run, they have already defeated the system.

Routing input is attacker-controlled text. Deterministic routing is reproducible, auditable,
has bounded latency, and cannot be talked out of running the malware agent. An LLM router is
available behind `ENABLE_LLM_ROUTER=true` and is constrained so the model may only **add**
agents to the mandatory set, never remove one (`router.py`). For five agents, running
everything concurrently costs one round-trip of wall clock, so selective routing is an
optimisation for tenant scale, not for a POC.

**Communication.** `AnalysisRequest` in, the same `AnalysisRequest` out on five edges.

**Agent Framework concept.** `add_fan_out_edges` and shared `State` (`ctx.set_state`).
State is used rather than widening the message because fan-in is typed on
`list[AgentVerdict]` — the analysis context has to travel some other way.

**In production.** Routing becomes tenant policy: an organisation may license only some
detectors, or apply different agent sets to different mailboxes. That is exactly the shape
of Defender's per-policy configuration, and it stays deterministic there too.

---

## 3. The five detection agents — `Executor` + `Agent`

Each specialist (`agents/*.py`) is one class that is simultaneously a workflow node and the
owner of an LLM agent. Its `run_analysis` runs the three layers described in the README.

**Why an executor that owns an agent, and not just an agent?** Because a detection specialist
has to do three things the model cannot: call deterministic tools, apply weighted rules, and
fuse the two under a floor the model cannot cross. Exposing the raw `Agent` as the graph node
would put the model in charge of its own score.

**Why five agents instead of one prompt?** Four concrete reasons, all visible in the output:

1. **Different evidence.** BEC has no links and no attachments; malware detection barely
   reads the body. One prompt covering both is a worse prompt for each.
2. **Different failure modes.** A crashed malware agent must fail closed. A crashed spam
   agent should not hold the queue. One agent cannot have two failure policies.
3. **Different actions.** Spam goes to Junk; malware is quarantined; BEC needs a human. The
   policy engine can only make that distinction if the scores arrive separately.
4. **Independent corroboration.** `R6_composite_escalation` fires when several agents each
   see something medium-confidence. That signal does not exist if there is only one opinion.

**Communication.** `AnalysisRequest` in, `AgentVerdict` out — never free text. The `Agent`
inside is given `response_format=LLMAssessment`, so a structured decode is requested from the
runtime where it is supported.

**Agent Framework concepts.** `Executor` + `@handler` (typed nodes), `Agent` (the reasoning
component), `tool()` / `FunctionTool` (the model-facing surface), structured outputs, and
per-agent `asyncio.wait_for` timeouts.

**Why right for email security.** It mirrors how detection actually works in a mail security
product: several independent detonation/heuristic/ML verdicts feeding one risk engine, not
one monolithic classifier.

**In production.** Several of these become calls to existing Microsoft detection services
rather than local logic — Safe Attachments detonation for malware, SafeLinks and MDTI for
URLs, mailbox-intelligence impersonation models for BEC. The agent survives as the component
that *interprets and correlates* those verdicts; the tools underneath it are replaced.

### The agents, briefly

| Agent | Fires on | Distinctive logic |
|---|---|---|
| `spam_agent` | Unsolicited bulk mail | Suppresses authenticated known-good senders with a working unsubscribe (legitimate marketing is not spam) |
| `phishing_agent` | Credential theft | Correlates four families — identity, authentication, destination, intent — and requires corroboration; authentication failure **alone** is capped below the action floor |
| `malware_agent` | Payload delivery | Static-only; fails closed; scores enable-content lures only when a payload is actually present |
| `bec_agent` | Fraud and impersonation | Leans on relational signals; the "BEC triad" of asserted authority + financial action + suppressed verification |
| `url_agent` | Link-borne risk | Independent link verdict, including the declared target of open redirectors |

---

## 4. The tools layer — pure functions

`tools/` holds `check_url`, `check_domain`, `detect_lookalike_domain`, `analyze_email_headers`,
`check_spf/dkim/dmarc`, `analyze_attachment_metadata`, `calculate_file_hash`,
`analyze_text_features` and the mock threat-intel source.

**Why tools, not agents?** Because the answers are checkable. "Does this domain resemble
microsoft.com by homoglyph substitution?" has a right answer that a function can compute and a
test can assert. Asking a model costs a round-trip, adds variance, and produces an answer
nobody can audit. **The rule: if it can be computed, compute it. Reserve the model for
judgement.**

**Communication.** Called directly by executors (wrapped in `timed_tool`, which populates the
audit trail), and exposed to models through `tools/agent_tools.py`.

**Why two surfaces?** The internal functions take rich objects and injectable dependencies —
right for internal use, wrong for a tool schema. `agent_tools.py` is a flat, primitive-only
adapter with docstrings written for a model to read. It is also, deliberately, exactly the
five-function surface an MCP security server would expose (see MIGRATION.md).

**Agent Framework concept.** `tool()` / `FunctionTool`, and `Agent(tools=…)`.

**In production.** The mock threat intel is replaced by Microsoft Defender Threat
Intelligence, the URL reputation service and the tenant's allow/block lists. The function
signatures do not change, which is the entire point of putting them behind this seam.

---

## 5. `RiskAggregatorExecutor` — fan-in

**What it does.** Merges N `AgentVerdict`s into one `AggregatedRisk`: a stable score
dictionary, a dominant threat class, a risk score, a confidence, and — critically —
**coverage**, the fraction of dispatched agents that actually reported.

**Agent, executor or tool?** An **executor** with no model. Aggregation is arithmetic plus
tie-breaking rules; both should be reproducible and testable.

**Three decisions worth explaining:**

- **Risk score is `max` plus corroboration, not a mean.** A 0.95 malware score must not be
  diluted by four agents correctly reporting 0.0 for their own specialities. Corroborating
  agents above 0.5 add a small increment.
- **Class ties break by consequence.** `MALWARE > PHISHING > BEC > IMPERSONATION > SPAM`, and
  a confirmed payload (≥0.85) outranks whatever pretext carried it — a malicious attachment
  wrapped in a brand-impersonation lure is *malware*, because the payload determines
  containment, forensics and the hunt query an analyst runs next.
- **Identity deception with no ask is `IMPERSONATION`, not phishing.** No credential request,
  no payload, no financial ask — quarantining is disproportionate and a human should look.
  That distinction changes the response, so it is made explicitly.

**Communication.** `list[AgentVerdict]` in (fan-in), `RiskBundle` out.

**Agent Framework concept.** `add_fan_in_edges` with a handler typed on `list[AgentVerdict]`:
the runtime waits for every branch before invoking it. Adding a sixth detection agent
requires no change here.

**In production.** This is where a trained ensemble model would sit, weighting detector
verdicts by their measured reliability rather than by hand-set priorities. Its output
contract stays identical.

---

## 6. `PolicyEngine` — the security boundary

**What it does.** Converts an `AggregatedRisk` into an enforceable `Decision`: eleven ordered
rules plus two fail-safe overrides.

**Agent, executor or tool?** Neither an agent nor a tool: a **pure policy component**, called
by the `PolicyExecutor` node. It contains no model and never sees message text — only scores.

**Why this must not be the LLM's job.**

- The email body is attacker-controlled input. A model that decides actions is a model an
  attacker can argue with.
- Mail flow decisions must be *reproducible*. The same message on Tuesday must get the same
  verdict as on Monday.
- They must be *auditable*. "R2 fired because phishing_score 0.96 ≥ 0.90" is an explanation
  an administrator can act on; "the model felt it was phishing" is not.
- They must be *changeable* by a security administrator without retraining or reprompting
  anything. Every threshold is an environment variable.

This is also how Defender for Office 365 is actually built: detonation and ML produce
verdicts, but anti-phishing policy, quarantine policy and tenant allow/block lists determine
what happens.

**Fail-safe (§16) is here, not in the agents.** Two overrides:

- **FS1** — if agent coverage drops below `POLICY_MIN_COVERAGE`, a message *cannot* be marked
  clean. Partial analysis is not a clean bill of health.
- **FS2** — if any agent did not complete, escalate to review, **and** refuse to label the
  message with a class that only the unresolved agent asserted. A crashed malware agent
  yields `SUSPICIOUS → HIGH_RISK_REVIEW`, not a fabricated `MALWARE` verdict and not `CLEAN`.

A rule that raises an exception is caught and ignored — a broken rule must never open the gate.

**Agent Framework concept.** The `PolicyExecutor` wrapping it is the source of an
`add_switch_case_edge_group`: `Case(requires_human_review) → HumanReviewExecutor`,
`Default → DeliveryExecutor`.

---

## 7. `HumanReviewExecutor` — the analyst in the loop

**What it does.** Two modes. `queue` (default) emits the decision immediately, flagged and
held — how a SOC queue actually behaves, and non-blocking. `request_info` **suspends the
workflow**, emits a request, and resumes when a `HumanReviewResponse` arrives; the analyst
overrides the policy, and the override is recorded in the decision's reasons and trace.

**Agent Framework concept.** `ctx.request_info()` plus `@response_handler` — the framework's
built-in human-in-the-loop primitive, with the workflow's state carried across the suspension.

**Why right for email security.** BEC is the case that needs it. The evidence is relational
rather than technical, the false-positive cost is a blocked legitimate payment, and the
false-negative cost is a wire transfer. Neither auto-quarantine nor auto-deliver is right;
a human with the evidence in front of them is.

**In production.** The suspension point becomes a Microsoft Sentinel incident or a Defender
quarantine review item, and the response arrives from the analyst's console — the workflow
code is unchanged.

---

## 8. The LLM provider layer

`models/llm_provider.py` is the only place in the repository that knows what a model is.

```
LLMProvider
  ├── OfflineProvider      → HeuristicChatClient  (no model; always available)
  ├── OllamaProvider       → agent_framework.ollama.OllamaChatClient
  ├── HuggingFaceProvider  → local transformers pipeline
  └── FoundryProvider      → Azure AI Foundry
```

**Why it exists.** So that migrating from a laptop to Foundry is `LLM_PROVIDER=foundry` plus
credentials, with no change to any agent, workflow, tool or policy. `FoundryProvider` is
intentionally the thinnest class in the file: it exists to prove the seam is real.

**The offline provider deserves a caveat.** `HeuristicChatClient` implements `BaseChatClient`
and returns a structured `LLMAssessment`, but it performs **no language modelling** — it reads
the machine-readable `<EVIDENCE>` block from the prompt and restates it, with confidence
capped at 0.45 because an evidence echo is not model confidence. Its purpose is to let the
whole architecture execute and be tested with no model and no network. A run under it is a
rules-only run, and the evaluation report says so in its header.

**Verification without a 5 GB download.** `tests/test_llm_provider.py` stands up a stub HTTP
server speaking the Ollama chat API and drives the *real* `OllamaChatClient` through it,
asserting that the JSON schema is pushed down to the runtime as `format` and that a full
detection agent fuses the returned score with its deterministic evidence. The Ollama path is
tested, not merely written.

---

## 9. Observability

`observability/logging.py` emits one JSON object per log line and collects spans per analysis.
Every record carries `correlation_id`, `email_id`, stage, duration, and stage-specific
attributes — the fields an OpenTelemetry span would carry, in the same shape, so exporting to
Foundry tracing or Application Insights is a change of sink rather than of instrumentation.

**One design note worth stealing.** The trace collector is *ambient*, resolved from a registry
by correlation ID, not carried on the message. Carrying it by value looked fine and silently
produced several partial traces, because workflow messages and shared State are copied as they
cross executor boundaries. A real tracer is ambient for exactly this reason. The regression
test is `test_trace_covers_the_documented_pipeline`.

---

## 10. Concurrency, and why there is a pool

`add_fan_out_edges` puts all five detectors in one superstep: total agent latency is `max()`,
not `sum()`. That is asserted by a test that makes every agent sleep 250 ms and requires the
whole analysis to finish in under 750 ms.

A single `Workflow` instance holds per-run state and refuses concurrent runs — the right
default, since a workflow is a unit of execution, not a server. Throughput therefore comes
from `PipelinePool`, which holds N independent pipelines sharing one model provider. That is
precisely how a production deployment scales: replicas behind a queue, one message per
replica at a time.

---

## What is deliberately *not* here

- **No dynamic detonation.** Static analysis only. Sandboxing hostile attachments safely is
  Defender's Safe Attachments, and doing it badly is worse than not doing it.
- **No live threat-intel calls.** The mock is offline by design; the seam for the real thing
  is `ThreatIntelSource`.
- **No MCP server yet.** The tool surface is MCP-shaped and isolated, but adding a server
  before there is a second consumer would be architecture for its own sake. See MIGRATION.md
  for when it earns its place.
- **No trained models.** Every score here comes from hand-written weights, which is
  appropriate for a POC and inappropriate for production. The aggregator is where a trained
  ensemble belongs.
