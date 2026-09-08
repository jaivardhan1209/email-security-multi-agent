# From local POC to Microsoft production

This document covers the four migrations the POC was designed to make cheap:
Microsoft Graph ingestion, Azure AI Foundry hosting, MCP tool serving, and integration with
Microsoft Defender for Office 365.

The short version, stated up front:

| Layer | Local POC | Production | Changes? |
|---|---|---|---|
| Ingestion | JSON fixtures | Microsoft Graph / Exchange transport | **Replaced** (one executor) |
| Queueing | in-process | Event Hubs / Service Bus | **Added** |
| Model runtime | Ollama + Qwen | Foundry-hosted model | **Config only** |
| Agents | `Executor` + `Agent` | identical | **Unchanged** |
| Workflow graph | `WorkflowBuilder` | identical | **Unchanged** |
| Agent contracts | `AgentVerdict` | identical | **Unchanged** |
| Tools | local pure functions | MDTI, SafeLinks, Safe Attachments, via MCP | **Replaced behind the seam** |
| Risk aggregation | hand-weighted | trained ensemble | **Reimplemented, same contract** |
| Policy engine | `risk_policy.py` | tenant anti-phishing / quarantine policy | **Reimplemented, same role** |
| Observability | JSON logs + spans | Foundry tracing / App Insights | **Sink swap** |
| Human review | `request_info` | Defender quarantine review / Sentinel incident | **Endpoint swap** |
| Enforcement | a `Decision` object | Defender mail-flow action | **Added** |

The agents, the graph, and the contracts between them — the parts that took the most design
effort — are the parts that do not change. That is the return on separating the LLM layer
from the tool layer from the policy layer.

---

## 1. Microsoft Graph / Outlook ingestion

**Target architecture**

```
Exchange Online mailbox
        │  (1) change notification: POST to your webhook
        ▼
Graph subscription  ──►  Event Hub / Service Bus  ──►  consumer replicas
                                                             │
                                                    IngestionExecutor
                                                             │
                                                    the workflow, unchanged
```

**Concretely**

1. **Register an Entra ID application** with application permissions
   `Mail.Read` (analysis) and `Mail.ReadWrite` (to move a message to Junk or quarantine).
   Scope it with an application access policy so it can only read the mailboxes in scope —
   `Mail.Read` at tenant level is otherwise a very large grant.
2. **Create a change-notification subscription** on `/users/{id}/messages` (or
   `/users/{id}/mailFolders/inbox/messages`), with `changeType=created` and a
   `notificationUrl` pointing at your endpoint. Subscriptions expire; renew on a timer.
   Validate the `clientState` on every notification and verify the validation token.
3. **Do not analyse in the webhook.** Acknowledge within Graph's timeout and enqueue. The
   webhook is a delivery receipt, not a processing pipeline.
4. **Fetch the full message** with
   `GET /users/{id}/messages/{messageId}?$expand=attachments` and
   `$select=internetMessageHeaders,...` — you specifically need
   `internetMessageHeaders` for `Authentication-Results`, which is where SPF/DKIM/DMARC
   results written by Exchange Online Protection live. Without that header the phishing agent
   loses an entire evidence family.
5. **Map to the canonical model.** Already implemented:
   `IngestionExecutor.from_graph_message()` maps a Graph `message` resource onto `Email`, and
   `tests/test_workflow.py::TestIngestion` drives a Graph payload through the whole pipeline.
   `app.py analyze msg.json --source graph` runs it from the command line today.
6. **Attachment bytes.** Graph returns `fileAttachment.contentBytes` as base64. Populate
   `Attachment.content` from it and the static analysis gains magic-byte and macro-string
   detection. Never write those bytes to disk with an executable extension.
7. **Add tenant context.** `org_context` is populated locally by fixtures; in production it
   comes from the tenant: accepted domains (`/organization`), protected users and domains from
   the anti-phishing policy, the executive list from the directory, and known vendor domains
   from the mail-flow graph. Several BEC detections depend on it.

**Latency note.** Graph notifications are post-delivery: the message is already in the
mailbox. That makes this an *after-delivery* remediation model — the enforcement action is
soft-delete, move-to-junk, or a zero-hour purge equivalent. Pre-delivery blocking requires
sitting in the transport path, which is section 4.

---

## 2. Azure AI Foundry

**What changes:** two environment variables and a credential.

```bash
LLM_PROVIDER=foundry
AZURE_AI_PROJECT_ENDPOINT=https://<project>.services.ai.azure.com/api/projects/<name>
AZURE_AI_MODEL_DEPLOYMENT_NAME=<your-deployment>
pip install agent-framework-azure-ai azure-identity
```

`FoundryProvider.create_chat_client()` already builds an `AzureAIAgentClient` with
`DefaultAzureCredential`. Nothing in `agents/`, `orchestration/`, `tools/` or `policy/`
imports a model type, so nothing else moves.

**What you gain, and what you must then do:**

- **Managed identity, not keys.** `DefaultAzureCredential` picks up the workload identity in
  AKS or Container Apps. Do not put a key in the image; there is no key in this repo and there
  should not be one in production either.
- **Content filters and abuse monitoring** apply to your calls. Note that a security product
  analysing phishing mail sends the model text that is *designed* to look abusive. Expect to
  need an exemption or a filter configuration for legitimate security analysis, and to test it
  before launch — this surprises people.
- **Foundry tracing.** `observability/logging.py` emits the field set an OTel span carries.
  Replace the `TraceCollector` sink with an OTel exporter and set `OTEL_ENABLED=true`; agent
  runs then appear in the Foundry portal alongside token counts.
- **Evaluation.** Foundry's evaluation SDK can consume the same labelled corpus. Keep
  `evaluation/` as the offline gate and add Foundry evaluations for the model-dependent
  behaviour, since that is what changes when a deployment is upgraded.
- **Model choice.** The open-source model is no longer forced by hardware. Keep the
  `LLMProvider` seam anyway: it is what lets you A/B two deployments, and what lets you fall
  back to the local model if a region has an incident.

**What does not change and should not.** The deterministic floor, the policy engine and the
fail-safes stay exactly as they are. A better model does not make it safe to let the model
decide actions.

---

## 3. MCP

**Should MCP be used in the POC? No. Should it be planned for? Yes.**

MCP is a *transport* for tools. Today there is one consumer (this process) and the tools are
in-process Python functions. Adding a server would introduce a network hop, a process to run,
and a failure mode, in exchange for nothing.

MCP earns its place when the second consumer appears:

- a Security Copilot experience, or an analyst chat surface, wanting the same URL/domain
  lookups;
- other agent systems in the organisation that should use the *same* reputation logic rather
  than reimplementing it;
- tools that must run somewhere else — inside a network boundary, or against a licensed feed
  that must not be embedded in every workload.

**The preparation is already done.** `tools/agent_tools.py` is the flat, primitive-only,
model-facing surface, isolated from the internal implementations precisely so it can be lifted:

```
MCP Security Server
  ├── check_url             (static URL risk; never fetches)
  ├── check_domain          (reputation + brand-lookalike)
  ├── check_lookalike_domain
  ├── check_file_hash       (known-bad sample intelligence)
  └── check_attachment      (static metadata analysis)
```

Serving them is a wrapper around those five functions; consuming them is swapping
`tool(check_url)` for `MCPStreamableHTTPTool(...)` in each agent's `llm_tools()`. Agent
Framework ships `MCPStdioTool`, `MCPStreamableHTTPTool` and `MCPWebsocketTool`, so the client
side is configuration.

**One caution.** An MCP tool result is untrusted input to the model, exactly like the email
body. When these tools stop being local pure functions and start being remote services, the
deterministic layer must keep computing the indicators that drive the *score* — otherwise a
compromised or spoofed tool server becomes a way to influence verdicts.

---

## 4. Microsoft Defender for Office 365

This is the section where the POC's local logic mostly *goes away*, and the architecture
around it stays.

**Where this system would sit**

```
Internet ──► Exchange Online Protection (connection/anti-spam/anti-malware filtering)
                          │
                          ▼
             Defender for Office 365
             ├── Safe Attachments  (detonation)
             ├── Safe Links        (URL detonation + time-of-click)
             ├── Anti-phishing     (spoof intelligence, impersonation, mailbox intelligence)
             │                     │
             │                     ▼
             │        ┌──────────────────────────────┐
             │        │  THIS SYSTEM as a correlation │
             │        │  and reasoning layer over     │
             │        │  those verdicts               │
             │        └──────────────┬───────────────┘
             ▼                       ▼
      Zero-hour Auto Purge     Quarantine / Junk / Alert
                                     │
                                     ▼
                    Defender portal · Sentinel incident · analyst
```

**What is replaced by a real Microsoft service**

| POC component | Production replacement |
|---|---|
| `MockThreatIntel` | Microsoft Defender Threat Intelligence, tenant allow/block lists |
| `check_url` static analysis | Safe Links verdicts + URL reputation (with real detonation) |
| `analyze_attachment_metadata` | Safe Attachments detonation verdicts |
| `check_spf/dkim/dmarc` | EOP's `Authentication-Results` and spoof intelligence (already authoritative) |
| `detect_lookalike_domain` | Anti-phishing impersonation protection + mailbox intelligence |
| Hand-weighted aggregation | Defender's own ML verdicts, as *inputs* to the aggregator |

**What survives — and why this is still worth building**

Defender already produces excellent per-signal verdicts. What this architecture adds on top:

1. **Cross-signal reasoning with an explanation.** "Sender resembles a protected vendor,
   the reply-to diverges to a consumer mailbox, and the body requests a banking change" is a
   correlation across three subsystems, expressed in language an analyst can act on.
2. **A named-technique vocabulary.** `AgentVerdict.indicators` gives every finding a stable
   ID, which is what makes hunting queries and campaign clustering possible later.
3. **The tenant-specific layer.** Protected executives, known vendor domains, the internal
   process for bank-detail changes — the context that generic detection cannot have, and where
   BEC is actually won.
4. **A human-in-the-loop path with the evidence attached**, rather than a quarantine entry an
   analyst has to reconstruct from headers.

**Enforcement.** The POC's terminal state is a `Decision` object. In production that becomes
an action: Graph `move` to the Junk folder, a quarantine submission, a ZAP-equivalent purge
for already-delivered mail, or a Sentinel incident for the review path. That step belongs
behind its own executor with its own permissions, so that a bug in analysis cannot delete
mail — the same fail-safe reasoning that shapes the rest of the system.

**Deployment shape.** Container Apps or AKS, KEDA-scaled on queue depth, one `PipelinePool`
per replica, Foundry for the model, Key Vault for secrets, managed identity throughout,
Log Analytics for the JSON logs the system already emits.

---

## Suggested order

1. **Graph ingestion in read-only mode.** Analyse real mail, take no action, compare against
   what Defender already did. This is how you find out whether the detections generalise —
   the POC's evaluation numbers are in-sample and cannot tell you.
2. **Foundry for the model.** Config change; do it once real traffic makes local inference the
   bottleneck.
3. **Replace the mock intel with Defender TI**, one tool at a time, keeping the evaluation
   corpus green as a regression gate.
4. **Enable enforcement** for the highest-precision path only — confirmed malware — and widen
   from there as the false-positive rate is measured on real mail.
5. **MCP** when the second consumer exists, and not before.
