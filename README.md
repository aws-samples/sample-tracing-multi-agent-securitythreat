# Trace security threats in multi-agent pipelines with Amazon OpenSearch Service

> **DISCLAIMER:** This code is provided as a sample for educational and
> testing purposes only. Users must perform their own security review and due
> diligence before deploying any code to production environments. The code
> provided represents a baseline implementation and may not address all
> security considerations for your specific environment.

Companion demo for the blog post **"Trace security threats in multi-agent
pipelines with Amazon OpenSearch Service."**

Multi-agent AI systems introduce attack surfaces that traditional security tools
can't see. A prompt injection buried in an external document can hijack a
downstream agent with tool access. Sensitive data can leak across tenant
boundaries without triggering a single alert.

This project shows how to trace **both** threats through an agent pipeline using
Amazon OpenSearch Service as a security observability layer:

1. **Injection propagation graph** — trace how a malicious instruction hidden in
   an ingested document flows agent-to-agent until it reaches a tool call.
2. **Leak-path reconstruction** — trace how PII from one tenant's session
   surfaces in another tenant's response.

It combines three techniques on top of OpenSearch:

- **Embedding similarity** (kNN vector search) to follow injected text even when
  it is reworded.
- **PII pattern detection** to find sensitive values as they move.
- **Provenance tagging** to reconstruct the exact source-to-impact path.

Finally it shows the **guardrails** that stop these attacks before they reach
production.

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   external  →   │  Ingestion Agent   Reasoning Agent   Action   │  → tools
   documents     │  (parses docs)     (plans)           Agent    │    (DB, email)
                 └───────┬───────────────┬─────────────────┬─────┘
                         │  every hop is instrumented        │
                         ▼               ▼                   ▼
                 ┌──────────────────────────────────────────────┐
                 │           Amazon OpenSearch Service            │
                 │  agent-traces  (text, embeddings, provenance,  │
                 │                 tenant, tool calls, PII)       │
                 └───────┬───────────────────────────────┬───────┘
                         ▼                                 ▼
              Injection propagation graph      Leak-path reconstruction
              (kNN + provenance traversal)     (PII + provenance)
                         │                                 │
                         └──────────────┬──────────────────┘
                                        ▼
                                    Guardrails
```

## Embeddings

The default embedding provider is **Amazon Titan Text Embeddings V2**
(`amazon.titan-embed-text-v2:0`, 1024-dim), so you need AWS credentials with
Amazon Bedrock access. To run without AWS, set `EMBEDDING_PROVIDER=local` to use
the deterministic lexical fallback.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Uses an in-memory OpenSearch-compatible backend (no domain needed) and
# Amazon Titan embeddings by default. Requires AWS credentials.
export AWS_REGION=us-east-1
python -m scenarios.scenario_injection
python -m scenarios.scenario_leak

# No AWS? Use the local embedder fallback:
EMBEDDING_PROVIDER=local python -m scenarios.scenario_injection
```

### Running against real Amazon OpenSearch Service

Point the demo at a managed domain (the real `opensearch-py` client is used;
see `src/backends/opensearch_backend.py` for the exact index mapping and query
DSL used in the blog):

```bash
export OPENSEARCH_BACKEND=opensearch
export OPENSEARCH_ENDPOINT=https://search-my-domain.us-east-1.es.amazonaws.com
export OPENSEARCH_USE_SIGV4=true              # SigV4 auth (recommended)
export AWS_REGION=us-east-1
python -m scripts.ingest_to_domain            # load the demo data
python -m scripts.build_saved_objects         # generate dashboards + Dev Tools queries
```

See `dashboards/` for the generated OpenSearch UI saved objects, Dev Tools
queries, and the screenshot guide.

## Layout

| Path | What it is |
|------|-----------|
| `src/backends/` | OpenSearch client + in-memory backend (same query semantics) |
| `src/embeddings.py` | Pluggable embedding provider (Amazon Titan default, local fallback) |
| `src/pii.py` | PII pattern detection |
| `src/provenance.py` | Provenance tagging helpers |
| `src/agents/` | Instrumented ingestion / reasoning / action agents |
| `src/pipeline.py` | Wires the multi-agent pipeline + tracing |
| `src/detection/` | Injection graph, leak-path, guardrails |
| `scenarios/` | Two end-to-end, runnable attack + detection demos |
| `scripts/` | Ingest to a domain + generate OpenSearch UI saved objects / queries |
| `dashboards/` | Generated saved objects, Dev Tools queries, screenshot guide |
| `data/` | Sample benign tickets and the malicious ticket |

## Production hardening

Production needs real controls. Four areas to harden:

- **AWS Identity and Access Management (IAM).** The action agent gets the
  narrowest possible role. Deny dangerous actions (`ses:SendEmail`,
  `lambda:InvokeFunction`) by default, conditioned on a session tag. When the
  provenance check comes back clean, pass `provenance-clean=true` as a session
  tag on the assumed role, and gate tool permissions on that tag. If the tag is
  missing or `false`, `export_customer_list` and `send_email` are not callable.
  See the sample deny policy at
  [`policies/action-agent-deny-policy.json`](policies/action-agent-deny-policy.json).
- **Guardrails.** Use Amazon Bedrock Guardrails to block prompts that attempt
  privilege escalation or exfiltration. Enable content filters (the prompt-attack
  filter covers injection and jailbreak attempts) to reject known attack
  patterns before the model processes them. This replaces the regex-based
  `sanitize_document` marker stripping in `src/detection/guardrails.py`.
- **Alerting.** When a guardrail fires, emit an event to Amazon EventBridge.
  Route it to AWS Security Hub where your Security Operations Center (SOC)
  already triages everything else, and route critical findings to Amazon SNS or
  PagerDuty for real-time paging.
- **Threshold tuning.** Sweep the cosine cutoff on your labeled data and pick
  the knee of the precision-recall curve. Re-check whenever your ingestion mix
  changes. Start at 0.75–0.85 for Titan Text Embeddings V2; other models will
  need their own range.

### IAM least-privilege policies

The action agent is the only component with tool access, so it is the principal
to constrain. The two egress tools in this demo — `send_email` and
`export_customer_list` (see `DANGEROUS_INTENTS` in
`src/detection/guardrails.py`) — are the ones an attacker wants to reach.

The sample policy at
[`policies/action-agent-deny-policy.json`](policies/action-agent-deny-policy.json)
denies the AWS actions those tools would map to in production (`ses:SendEmail`,
`ses:SendRawEmail`, `lambda:InvokeFunction`) unless a `provenance-clean=true`
session tag is present on the assumed role. Attach the policy to the action
agent's execution role, and set the tag only after the provenance check in
`check_tool_call` returns `allowed=True`. If the tag is absent or `false`, IAM
denies the call even if the application-layer guardrail is bypassed, giving you
defense in depth rather than a single in-process check.

This is a starting template. Scope `Resource` to specific SES identities or
Lambda function ARNs rather than `*`, and add any other egress actions your
production tools use (for example `s3:PutObject` for file uploads).

### OpenTelemetry integration

This demo uses a custom tracer (`src/tracing.py`) that writes one span document
per agent hop directly to the `agent-traces` index. It is intentionally not an
OpenTelemetry implementation — the span is a plain JSON document whose fields
(`trace_id`, `span_id`, `parent_span_id`, `provenance`, `tenant_id`,
`session_id`, `pii_values`, `tool_calls`, `embedding`) are chosen so the
detectors can reconstruct lineage.

For production, you can migrate to OpenTelemetry without changing the detection
logic:

- Emit each agent hop as an OTel span, carrying the same custom attributes
  (`provenance`, `tenant_id`, `pii_values`, and so on) that the detectors rely
  on. The parent/child relationship OpenTelemetry tracks natively replaces the
  `parent_span_id` field this demo sets by hand.
- Export spans through the OpenTelemetry Collector to Amazon OpenSearch Service,
  then compute and attach the Amazon Titan embedding on ingest so the
  `knn_vector` field is still populated for similarity search.
- Keep the index mapping in `src/backends/opensearch_backend.py` as the target
  schema; the detectors in `src/detection/` query that schema regardless of how
  the spans were produced.

The OpenTelemetry GenAI semantic conventions are a good reference for naming the
agent and tool-call attributes consistently.

### Alerting pipeline setup

The two detectors map directly to two standing monitors, so detection runs
continuously instead of only after an incident. Both conditions come straight
from the demo's detection logic:

- **Injection monitor.** Flag any `phase: "act"` span whose `tool_calls` include
  an egress tool (`send_email` or `export_customer_list`) and whose `provenance`
  contains a `document:` tag. This is the OpenSearch Alerting equivalent of the
  provenance-to-impact query the blog walks through.
- **Cross-tenant leak monitor.** Flag any span where `pii_values` exists and the
  `provenance` carries a `user:` session that belongs to a different tenant than
  the span's `tenant_id`. This mirrors `check_response` in
  `src/detection/guardrails.py`, which redacts on cross-session PII provenance.

Wire each monitor's trigger to an Amazon SNS topic or an Amazon EventBridge
event bus. From EventBridge, route to AWS Security Hub for centralized triage,
and log every guardrail decision (block, allow, override) to an Amazon S3 bucket
with Object Lock for a tamper-proof audit trail.

## Disclaimer

This is educational sample code for a blog post. The agents are deterministic
simulators that intentionally "obey" injected instructions to demonstrate the
vulnerability and its detection. Do not use as-is in production.
