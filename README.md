# Email Security Multi-Agent POC

A Microsoft Defender-style, multi-agent email protection system built on **Microsoft Agent
Framework**, running entirely locally against **open-source models**. It detects spam,
phishing, malware, BEC, malicious URLs, suspicious attachments, impersonation, credential
harvesting and social engineering.

The point of this repository is the *architecture*: a clear separation between LLM agents,
deterministic executors, tools, orchestration and security policy — the distinction that
disappears when a system is really "call an LLM five times and merge the answers".

```
                              EMAIL (JSON today, Microsoft Graph later)
                                        │
                              ┌─────────▼─────────┐
                              │  IngestionExecutor │  normalize → canonical Email
                              └─────────┬─────────┘
                              ┌─────────▼──────────┐
                              │  OrchestratorExec  │  deterministic routing + shared State
                              └─────────┬──────────┘
                       ┌────────┬───────┼───────┬────────┐      ← fan-out: ONE superstep
                       ▼        ▼       ▼       ▼        ▼
                    Spam    Phishing  Malware  BEC      URL     ← Executor + Agent each
                     │         │        │       │        │
                     │      ┌──┴────────┴───────┴────┐   │
                     │      │  SECURITY TOOLS (pure) │◄──┘
                     │      │ url · domain · header  │
                     │      │ attachment · content   │
                     │      └───────────┬────────────┘
                       └────────┴───────┼───────┴────────┘      ← fan-in: list[AgentVerdict]
                              ┌─────────▼──────────┐
                              │  RiskAggregator    │  merge scores, classify, coverage
                              └─────────┬──────────┘
                              ┌─────────▼──────────┐
                              │   PolicyEngine     │  DETERMINISTIC. No model. Auditable.
                              └─────────┬──────────┘
                        ┌───────────────┴───────────────┐        ← switch/case routing
                        ▼                               ▼
                 HumanReviewExecutor            DeliveryExecutor
                        │                               │
              QUARANTINE│HIGH_RISK_REVIEW      DELIVER │ JUNK │ QUARANTINE
```

---

## The one design decision that matters

**The LLM never decides what happens to a message.**

Each detection agent runs three layers and fuses them with a formula the model cannot reach:

| Layer | What it is | Who owns it |
|---|---|---|
| 1. Tools | Pure functions producing checkable `Indicator`s | `email_security/tools/` |
| 2. Rules | Indicator weights combined by noisy-OR into a baseline score | `DetectionAgent.combine_indicators` |
| 3. Reasoning | An Agent Framework `Agent` returning a structured `LLMAssessment` | the model |
| **Fusion** | `max((1-w)·det + w·llm, det × floor)` | `DetectionAgent.fuse` |

The fusion is deliberately **asymmetric**: the model can raise a score freely, but can only
lower it to a configured floor (default 75%) of the rule-based score. A prompt-injected
email body can add false alarms; it cannot talk the system out of a known-bad file hash or a
brand-impersonating sender that failed DMARC.

Scores then go to a **policy engine** that is pure Python, has no model in it, is fully
unit-tested, and is configurable by environment variable. Every action is traceable to a
named rule: *"R2 fired because phishing_score 0.96 ≥ 0.90"*.

---

## Quickstart

```bash
git clone <this repo> && cd email-security-multi-agent

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt          # or: make install

.venv/bin/python app.py doctor                     # which model runtimes are available?
.venv/bin/python app.py graph                      # print the live workflow topology
.venv/bin/python app.py demo                       # four contrasting messages
.venv/bin/python -m email_security.evaluation.evaluate   # full 60-message evaluation
.venv/bin/python -m pytest                         # 146 tests
```

It runs immediately with **no model installed**: the `offline` provider is a deterministic
stub that satisfies the `BaseChatClient` contract, so the entire architecture — agents,
workflow, concurrency, structured outputs, policy, human-in-the-loop — executes end to end
while the reasoning layer contributes nothing. That is a scaffold for development and CI,
not a language model, and the evaluation report says so.

### Enabling a real open-source model

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct        # ~4.7 GB, the recommended default

cp .env.example .env
sed -i 's/^LLM_PROVIDER=offline/LLM_PROVIDER=ollama/' .env

.venv/bin/python app.py doctor         # should now report ollama available
.venv/bin/python app.py demo
```

**Model choice.** `qwen2.5:7b-instruct` is the default because it has the best
instruction-following and JSON-schema adherence per gigabyte in this size class, which is
what a structured-output pipeline actually needs. Alternatives, all a one-line change:

| Model | RAM/VRAM | Notes |
|---|---|---|
| `qwen2.5:7b-instruct` | ~6 GB | **default** — best structured-output adherence |
| `llama3.1:8b-instruct` | ~6.5 GB | stronger open-ended reasoning, slightly looser JSON |
| `mistral:7b-instruct` | ~5 GB | fastest of the three, weakest at schema adherence |
| `qwen2.5:3b-instruct` | ~3 GB | CPU-only or <8 GB machines |

### Docker

```bash
docker build -t email-security-poc .
docker run --rm email-security-poc evaluate                      # deterministic layer only
docker run --rm --add-host=host.docker.internal:host-gateway \
  -e LLM_PROVIDER=ollama -e OLLAMA_HOST=http://host.docker.internal:11434 \
  email-security-poc demo                                        # with a local model
```

The image contains no model. The same image runs against Ollama locally and an Azure AI
Foundry endpoint in production — only `LLM_PROVIDER` and the injected credentials change.

---

## Web inspector

```bash
make ui                 # or: .venv/bin/python server.py   →  http://127.0.0.1:8800
```

A single-page inspector for pasting an email and watching the pipeline run. It does **not**
re-implement detection in the browser: the page posts the email, the server runs
`workflow.run(stream=True)`, and every Agent Framework `WorkflowEvent` is forwarded over
Server-Sent Events as it happens. What animates is the real execution.

It shows four things the terminal output cannot:

| Panel | What it makes visible |
|---|---|
| **Live workflow** | Nodes light up as `executor_invoked` / `executor_completed` arrive, grouped by superstep — the five detection agents visibly start together, then tint green/amber/red by score |
| **Agent verdicts** | A fusion bar per agent with four markers: the rule score, the model score, the **deterministic floor** the model cannot push below, and the agent's assert threshold. This is the asymmetric-fusion rule made visual |
| **Risk aggregation → policy** | The score table, the risk formula with its numbers substituted, then **all eleven policy rules** with the fired ones highlighted — so you can see what did *not* fire, which is usually the more interesting half |
| **Execution timeline** | Agent bars overlapping in one superstep. Sequential execution would draw a staircase |

The sample dropdown loads all 60 corpus messages (with their ground-truth labels and the note
explaining why each is hard) and the eight held-out samples. Or paste your own JSON — a
Microsoft Graph `message` resource is auto-detected and normalized.

The provider badge turns amber when no real model is running, because a screenshot of this UI
would otherwise imply the model contributed something it did not.

---

## Commands

| Command | What it does |
|---|---|
| `app.py doctor` | Probe every model runtime; explain what the system will actually use |
| `app.py graph` | Print the built workflow as Mermaid |
| `app.py analyze data/samples/phishing_example.json --trace` | Analyze one email file (`-` reads stdin) |
| `app.py analyze msg.json --source graph` | Analyze a raw Microsoft Graph `message` resource |
| `app.py corpus phish-001 --trace` | Analyze a labelled corpus message and show ground truth |
| `app.py demo` | Four contrasting messages: legitimate, phishing, BEC, malware |
| `make samples` | Analyze the eight held-out sample messages in `data/samples/unseen/` |
| `app.py review bec-002 --decision QUARANTINE` | Walk through the blocking human-in-the-loop path |
| `app.py evaluate -- --concurrency 8 --json results.json` | Full evaluation harness |
| `server.py --host 0.0.0.0 --port 8800` | Serve the web inspector |

---

## Example output

A CEO-fraud message. Note that only the BEC agent fires — the phishing, malware, URL and
spam agents correctly stay silent, which is what separates a multi-agent system from one
prompt asking about everything at once:

```
MESSAGE  bec-002
From     Robert Chen (CEO) <ceo.robert.chen@outlook.com>
Subject  Urgent wire — confidential acquisition
----------------------------------------------------------------------------
VERDICT  BEC  ->  HIGH_RISK_REVIEW
         risk=0.999  confidence=0.925  latency=240 ms
         HELD FOR ANALYST REVIEW

AGENT SCORES
  bec_agent       0.999 ████████████████████ det=1.00 llm=0.999 conf=0.93   6.7ms
  phishing_agent  0.150 ███                  det=0.15 llm=0.15  conf=0.75  13.2ms
  spam_agent      0.000                      det=0.00 llm=0.0   conf=0.70  24.9ms
  malware_agent   0.000                      det=0.00 llm=0.0   conf=0.70   4.4ms
  url_agent       0.000                      det=0.00 llm=0.0   conf=0.70   1.9ms

POLICY
  rules fired: R4_bec_review

REASONS
  - bec_agent: Executive authority claimed from a consumer mailbox (outlook.com)
  - bec_agent: Display name matches a known executive but the sender is external
  - bec_agent: Financial detail present: 'banking_coordinates'
  - [R4_bec_review] BEC score at or above the review threshold — money movement needs a human
```

And the full `--trace`, which is the §10 data flow made visible:

```
EMAIL_RECEIVED            0.00 ms  sender=ceo.robert.chen@outlook.com
EMAIL_NORMALIZED          0.00 ms  recipients=1
ORCHESTRATOR_STARTED      0.05 ms  router=deterministic
AGENTS_DISPATCHED         0.00 ms  agents=spam,phishing,malware,bec,url mode=deterministic
phishing_agent.tools      8.69 ms
phishing_agent.llm        4.45 ms  model=heuristic-offline
phishing_agent.verdict   13.20 ms  score=0.15 deterministic=0.15 llm=0.15 tools=5
url_agent.…               1.90 ms
spam_agent.…             24.85 ms
malware_agent.…           4.42 ms
bec_agent.verdict         6.65 ms  score=0.9993 deterministic=0.9995 llm=0.999 tools=3
AGENT_RESULTS_COLLECTED   0.19 ms  verdicts=5
RISK_AGGREGATED           0.00 ms  risk_score=0.9993 dominant=BEC coverage=1.0
POLICY_ENGINE             0.21 ms  rules=11
POLICY_EVALUATED          0.00 ms  action=HIGH_RISK_REVIEW rules=R4_bec_review
HUMAN_REVIEW_QUEUED       0.00 ms  proposed_action=HIGH_RISK_REVIEW
FINAL_DECISION            0.00 ms  action=HIGH_RISK_REVIEW held_for_review=True
```

Every agent span sits in the same superstep — five agents, ~25 ms wall clock, not the sum
of their runtimes. `tests/test_workflow.py::test_detectors_run_in_one_superstep_not_in_sequence`
asserts this rather than assuming it.

---

## Evaluation

60 labelled synthetic messages (`data/emails/`), including deliberate control cases and
borderline pairs. Run with the default `offline` provider:

```
-- FINAL CLASSIFICATION ---------------------------------------------------
  accuracy (class)       98.3%
  accuracy (action)      98.3%
  macro F1               0.986

  class            support    prec  recall      F1   TP   FP   FN
  BEC                    8   1.000   1.000   1.000    8    0    0
  CLEAN                 15   0.938   1.000   0.968   15    1    0
  IMPERSONATION          8   1.000   1.000   1.000    8    0    0
  MALWARE                9   1.000   1.000   1.000    9    0    0
  PHISHING              10   1.000   1.000   1.000   10    0    0
  SPAM                  10   1.000   0.900   0.947    9    0    1

-- THREAT vs CLEAN --------------------------------------------------------
  precision 1.000   recall 0.978   F1 0.989
  false positive rate   0.0%    (clean mail wrongly actioned)
  false negative rate   2.2%    (threats delivered to the inbox)

-- SECURITY-CRITICAL FALSE NEGATIVES --------------------------------------
  none — no phishing, malware or BEC message was delivered

-- PER-AGENT PERFORMANCE --------------------------------------------------
  agent              prec  recall     F1  in-cls  out-cls    sep      ms
  bec_agent         1.000   0.875  0.933   0.841    0.364  0.476    13.4
  malware_agent     1.000   1.000  1.000   0.941    0.000  0.941    12.4
  phishing_agent    1.000   1.000  1.000   0.970    0.308  0.662    12.6
  spam_agent        1.000   0.800  0.889   0.724    0.239  0.486    13.8
  url_agent         1.000   0.833  0.909   0.851    0.148  0.702    10.7

  p50 239 ms   p90 257 ms   p99 282 ms      60 messages in 5.4 s at concurrency 4
```

**Read these numbers honestly.**

1. **They are in-sample.** The corpus is synthetic, written for this project, and the
   detector weights were tuned against it. This is a regression baseline that catches
   refactoring damage — not an estimate of production accuracy. Real evaluation needs held-out
   mail from a real tenant.
2. **They measure the deterministic layer.** With `LLM_PROVIDER=offline` no language model
   runs. The rule layer handles the structural attacks (lookalike domains, auth failures,
   double extensions, macro indicators) because those are genuinely rule-shaped problems.
3. **The single miss shows where the model earns its place.** `spam-010` is graymail:
   authenticated, well-formed, a working unsubscribe link, indistinguishable *structurally*
   from the legitimate newsletter `leg-006`. No rule separates them, because the difference
   is whether the recipient wanted it. That is a semantic judgement, and it is exactly the
   class of decision the LLM layer exists for. Point `LLM_PROVIDER` at a real model and this
   is the case to watch.

The evaluation exits non-zero if any phishing, malware or BEC message is delivered, so it
works as a CI gate.

### Held-out samples

`data/samples/unseen/` holds eight messages written *after* the detectors were tuned, using
lures that appear nowhere in the corpus — a Teams voicemail phish, an `.iso` purchase order,
a supplier remittance-change from a consumer mailbox, a crypto webinar promotion, an internal
service-desk impersonation, and three legitimate messages (Slack, an internal survey that
mentions passwords, an AWS bill full of financial language). Run them with `make samples`.

They found three real defects on first run, all now fixed with tests:

| Defect | Fix |
|---|---|
| A crypto *mention* in marketing copy scored as a crypto *payment request*, escalating spam into the analyst queue | Split the lexicon: `cryptocurrency_mention` (weak) vs `cryptocurrency_payment_request` (strong) |
| `.iso` attachments were weighted like a `.zip`, despite being chosen specifically because mounting one strips the Mark-of-the-Web | Separate `MOTW_BYPASS_EXTENSIONS` class, plus a malware-agent correlation bonus the other agents already had |
| `org_domain_lookalike` was missing from the aggregator's identity-marker set, so impersonation of the tenant's *own* domain was classed as phishing and quarantined | Added to the set; and `R2`/`R3`/`R6` now stand down for `IMPERSONATION` so `R5` — which was previously unreachable — decides |

That last one is worth noting: `R5_impersonation_review` could never fire, because the
phishing rules always quarantined first. A policy rule that cannot fire is a bug, and only
unseen input surfaced it.

---

## Configuration

Everything is environment-driven; see `.env.example`. No secrets in code.

```bash
LLM_PROVIDER=offline            # offline | ollama | huggingface | foundry
LLM_MODEL=qwen2.5:7b-instruct
OLLAMA_HOST=http://localhost:11434

AGENT_TIMEOUT_SECONDS=45        # per-agent LLM budget
AGENT_LLM_WEIGHT=0.4            # weight of the model opinion in fusion
AGENT_DETERMINISTIC_FLOOR=0.75  # the model can only lower a score to 75% of the rule score
ENABLE_LLM_ROUTER=false         # opt-in model-proposed routing (can only widen coverage)

POLICY_MALWARE_QUARANTINE=0.90  # ── the security policy, tuned by an administrator ──
POLICY_PHISHING_QUARANTINE=0.90
POLICY_BEC_REVIEW=0.90
POLICY_SPAM_JUNK=0.85
POLICY_COMPOSITE_QUARANTINE=1.55
POLICY_MIN_COVERAGE=0.80        # below this agent coverage a message cannot be called clean
POLICY_HUMAN_REVIEW=true
```

---

## Failure handling

Failures are contained per agent and resolved **fail-safe, never fail-open**:

| Failure | Behaviour |
|---|---|
| A tool raises | Agent verdict `degraded=True`, score floored at 0.50 uncertainty |
| Model unreachable | Provider health check degrades to offline at startup; verdicts marked degraded |
| Model times out | `asyncio.wait_for` per attempt, then retry, then deterministic-only |
| Model returns malformed JSON | Salvage the first balanced JSON object; clamp out-of-range fields; else retry |
| An agent crashes entirely | Its verdict is missing → aggregate `coverage` drops → policy rule **FS1** blocks a clean verdict |
| The malware (or any) agent never completes | Policy rule **FS2** escalates to review, and refuses to *label* the message with a class that only an unresolved agent asserted |

That last point matters: a crashed malware agent must not produce "MALWARE — delivered"
*or* "CLEAN — delivered". It produces `SUSPICIOUS → HIGH_RISK_REVIEW`, which is what an
analyst can actually act on.

---

## Project structure

```
email_security/
├── agents/              spam · phishing · malware · bec · url  (Executor + Agent each)
│   └── base.py          the three-layer + fusion contract every agent inherits
├── orchestration/
│   ├── workflow.py      WorkflowBuilder graph, EmailSecurityPipeline, PipelinePool
│   ├── executors.py     ingestion · orchestrator · aggregator · policy · HITL · delivery
│   └── router.py        deterministic routing (default) and opt-in LLM routing
├── tools/               url · domain · header · attachment · content · threat_intel
│   └── agent_tools.py   the flat, model-facing surface — and the future MCP server surface
├── models/
│   ├── schemas.py       every cross-boundary contract (Email, AgentVerdict, Decision…)
│   ├── llm_provider.py  Offline | Ollama | HuggingFace | Foundry
│   └── heuristic_client.py  the no-model BaseChatClient stub
├── policy/risk_policy.py    deterministic rules + fail-safe overrides
├── observability/           structured JSON logging + span collection
└── evaluation/              corpus loader, metrics, evaluation runner

data/emails/            60 labelled synthetic messages across 6 categories
tests/                   146 tests: tools, agents, policy, aggregation, workflow, providers
docs/ARCHITECTURE.md    component-by-component walkthrough — what each part is and why
docs/MIGRATION.md       Foundry, Microsoft Graph, Defender for Office 365, MCP
```

---

## Safety

This is a defensive system and it stays defensive:

- Attachments are **never** executed, opened with a handler, unpacked to disk, or downloaded.
  Analysis is filenames, declared MIME types, magic bytes, printable strings and hashes.
- URLs are **never** fetched, resolved or visited. They are parsed and scored statically,
  including the declared target of an open redirector.
- Threat intelligence is a local, static mock. No network calls to any live infrastructure.
- Email bodies are treated as untrusted attacker-controlled data in every prompt, and the
  deterministic floor limits what a successful prompt injection can achieve.
- The container runs as a non-root user, because this process parses hostile input by design.

## Further reading

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — every component: what it does, why it is
  an agent vs an executor vs a tool, how it communicates, which Agent Framework concept it
  demonstrates, why that suits email security, and what changes in a real Defender deployment.
- **[docs/MIGRATION.md](docs/MIGRATION.md)** — the path to Microsoft Graph ingestion, Azure AI
  Foundry hosting, MCP tool serving, and integration with Defender for Office 365.
