---
name: threat-modeling
description: >
  This skill should be used when the user asks to "threat model this ticket/repo/pipeline",
  "run a threat model against our Jira epic and repo", "generate a STRIDE analysis from our
  Jenkins pipeline and ServiceNow change", "run a PASTA threat model", "build a threat model
  report with a draw.io diagram", "create an attack chain mapping for this service", "check
  compensating controls and give me additional controls for partial compliance", "threat model
  our LLM app / RAG pipeline / AI agent", "map this to OWASP Top 10 / OWASP API Security Top 10 /
  OWASP LLM Top 10", "map this attack chain to MITRE ATT&CK / MITRE ATLAS", or any request to
  produce a security threat model that pulls live context from Jira, Jenkins, ServiceNow, or a
  code repository via the connectors in this plugin. Also trigger for "give me the threat model
  as Word/Excel" or "regenerate the DFD as draw.io". Covers conventional application/API systems
  and AI/ML/LLM infrastructure (training pipelines, model registries, vector stores/RAG, inference
  endpoints, agentic tool-use) alike. Always use this skill when the user wants an end-to-end
  threat model backed by ticketing/CI/CD/repo data rather than a manually pasted description.
metadata:
  version: "0.2.0"
---

# Threat Modeling Skill

Pulls live context from Jira, Jenkins, ServiceNow, and a code repository via this plugin's MCP
connectors, then runs an end-to-end threat model covering both conventional application/API systems
and AI/ML/LLM infrastructure: a data flow diagram, trust boundaries and threat actors, a STRIDE
threat register scored for likelihood and business impact (optionally the full 7-stage PASTA process
for higher-rigor engagements), a compensating-controls and mitigation-assurance assessment, a
compliance gap analysis, and every threat and attack-chain step mapped to the relevant OWASP Top 10
list(s) — OWASP Top 10 (web AppSec), OWASP API Security Top 10, and OWASP Top 10 for LLM
Applications — plus MITRE ATT&CK / MITRE ATLAS technique IDs. Deliverables: a draw.io-compatible DFD,
a draw.io-compatible threat model diagram (trust boundaries + threat actors), a Word report, and/or
an Excel risk register — whichever output formats the user asks for.

**Why pull from tools instead of asking for a description:** a ticket or repo almost always contains
more architectural truth than a user can recite from memory — auth middleware in the repo, actual
deploy steps in Jenkins, prior incidents in ServiceNow, or AI-framework usage (LangChain, a vector DB
client, a model-serving container) that tells you this is an AI-scoped system before the user even
says so. Grounding the model in that material produces a more accurate DFD and catches things a
manual description would miss.

**Why Sonnet by default:** `scripts/summarize.py` is called to compress large raw payloads (console
logs, big ticket threads, large repo files) before they enter this session's context. It defaults to
`claude-sonnet-5` — a strong cost/quality balance for extractive summarization — via the `MODEL_NAME`
env var. Point it at another available model (see `config/model-config.example.json`) if the user
wants higher-fidelity summaries (`claude-opus-4-8`) or lower cost on high-volume pulls
(`claude-haiku-4-5-20251001`). This only affects the summarization helper — the main threat-modeling
reasoning always runs on whichever model is driving the current session.

**Running this outside Claude Code / Cowork:** this skill's instructions, reference docs, and Python
scripts are plain markdown/JSON/Python with no Claude-specific dependencies, so the same workflow
runs under OpenAI Codex CLI (via the root `AGENTS.md`) and Cursor (via `.cursor/rules/threat-modeling.mdc`
and `.cursor/mcp.json`) — see `README.md`'s "Using this plugin outside Claude Code" section for setup
per tool. Whichever agent is driving, follow this file and its `references/` the same way.

---

## Execution Steps

### Step 1 — Scope the assessment

Ask the user (only what's not already given):
- Which system/service is being threat modeled, and what's the goal (new feature review, periodic
  reassessment, pre-launch gate, compliance audit follow-up)? A compliance audit follow-up or
  pre-launch gate on a regulated system is a signal to run full PASTA (`references/pasta-methodology.md`)
  rather than the lightweight STRIDE-plus-scoring default — ask explicitly if unclear.
- Does the system include any AI/ML/LLM components (model training/fine-tuning, a model registry, a
  vector store/RAG pipeline, an inference endpoint, an agentic tool-calling layer)? If unsure, use
  the repo connector's `detect_ai_stack` tool once repo access is available (Step 2) rather than
  guessing — a positive hit means walking `references/ai-threat-taxonomy.md` in full alongside
  standard STRIDE.
- Which of the four connectors apply: Jira ticket/epic key, Jenkins job path, ServiceNow
  record/table, code repo owner+name? Skip any not relevant — none are mandatory.
- Desired output format(s): Word, Excel, or both. Default to both if the user doesn't say.

If a connector isn't configured yet (missing env vars — the tool call will raise a clear error
naming the missing variable), tell the user which `.env` values to set per `README.md` and continue
with whatever sources ARE available rather than blocking entirely.

### Step 2 — Pull context via connectors

Call the relevant MCP tools:
- **Jira**: `get_issue` for the epic/ticket, `get_epic_children` to enumerate scope, `search_issues`
  for related tickets (e.g. prior security findings tagged on the same component).
- **Jenkins**: `get_job` for pipeline config (parameters often reveal secrets/inputs),
  `get_build` for what a deploy actually does, `get_console_log_tail` only if the build/deploy
  logic isn't already clear from job config.
- **ServiceNow**: `get_record` for a specific change/incident, `search_table` for related history,
  `get_compliance_gaps` to seed real, tracked compliance gaps rather than only inferred ones.
- **Repo**: `list_tree` to survey structure, `get_file` on entry points / IaC / auth middleware /
  CI config, `search_code` for secrets/auth/deserialization patterns, `get_recent_commits` to spot
  recently-changed high-churn areas, and `detect_ai_stack` early to determine whether
  `references/ai-threat-taxonomy.md` applies to this system.

**Token minimization:** if any single payload is large (a console log tail, a big ticket
description, a large repo file), pipe it through `scripts/summarize.py --focus "..."` before treating
it as part of the analysis context, rather than reading the raw payload in full. Use a focus string
naming what matters for this specific system (e.g. `"auth flow, data stores, outbound calls"` or, for
an AI-scoped system, `"prompt handling, tool/agent permissions, training data sources, model serving"`).

### Step 3 — Model the system: DFD + trust boundaries + threat actors

From the pulled context, derive: actors/components (external entities, processes, data stores,
external systems, and — where AI-scoped — the AI/ML pipeline component types from
`references/ai-threat-taxonomy.md`: training pipeline, model registry, vector store, inference
endpoint, agent/tool layer), numbered data flows between them, trust boundaries (where untrusted
actors or third parties cross into trusted infrastructure — including the boundary between a
prompt/RAG-context input and the model's own trusted instruction scope), and threat actors relevant
to each boundary crossing (unauthenticated external attacker, compromised insider, compromised CI
credential, compromised third-party vendor, malicious prompt/document author, etc.).

Express this as a JSON spec matching `references/examples/sample_threat_model_spec.json` (see also
`references/examples/sample_ai_threat_model_spec.json` for an AI-scoped worked example), then run:

```
python3 scripts/generate_drawio.py <spec.json> <Service>_DFD.drawio dfd
python3 scripts/generate_drawio.py <spec.json> <Service>_Threat_Model.drawio threat_model
```

Both are directly importable at https://app.diagrams.net — fully editable, not flattened images.
Deliver both files alongside the report.

### Step 4 — STRIDE threat register with risk scoring and framework mapping

Follow `references/stride-methodology.md` in full — it defines the six STRIDE categories, the
minimum-threats rule, and the Likelihood × Impact scoring rubric (PASTA-inspired business-impact
grounding). If AI/ML components are in scope, also follow `references/ai-threat-taxonomy.md` for the
AI-specific threats layered onto each category. Do not skip the scoring step or cluster every threat
at Medium.

For every threat, also tag `owasp_id` (one or more IDs from `references/owasp-mappings.md` — OWASP
Top 10, OWASP API Security Top 10, and/or OWASP Top 10 for LLM Applications, whichever list(s) apply
to that component) and, where the threat maps cleanly to adversary tradecraft, note the relevant
MITRE technique per `references/mitre-mappings.md` (used explicitly in Step 6's attack chains, but
useful to identify here too).

If running full PASTA (see Step 1), also complete PASTA Stage 5 (Vulnerability and Weakness
Analysis) from `references/pasta-methodology.md`: walk each in-scope component's applicable OWASP
list top to bottom as a checklist, confirming every category is either represented by a threat or
explicitly ruled out.

### Step 5 — Compensating controls and mitigation assurance

Follow `references/compensating-controls-and-gaps.md`. For every threat: document existing
compensating controls (or say plainly none were found), estimate probability of successful
mitigation, compute residual risk after the primary fix and existing controls, and list additional
controls required for complete closure.

### Step 6 — Attack chain mapping with MITRE ATT&CK / ATLAS tagging

Follow `references/attack-chain-mapping.md`. Identify at least one plausible attack chain linking
two or more individual threats into an end-to-end scenario with real business consequence — this is
what turns an itemized threat list into a narrative a risk owner can act on. For each step in a
chain, tag `mitre_attack_technique` and/or `mitre_atlas_technique` per `references/mitre-mappings.md`
— ATT&CK for conventional infrastructure tradecraft, ATLAS for steps targeting an AI/ML component
specifically. If running full PASTA, this is Stage 6 (Attack Modeling / Simulation).

### Step 7 — Compliance gap analysis

Cross-reference `get_compliance_gaps` output (if ServiceNow is connected) and any partially-met
controls surfaced during analysis. For each: name the control, its compliance status, the specific
gap, and the additional controls needed to reach full compliance. If ServiceNow isn't connected,
derive gaps from the compensating-controls analysis in Step 5 instead — a control with existing
compensating measures but no primary mitigation in place is a compliance gap candidate.

### Step 8 — Build the report data and render outputs

Assemble one JSON object matching `references/report-data-schema.json` (worked examples:
`references/examples/sample_report_data.json` and `references/examples/sample_ai_report_data.json`)
containing every section built above, including the `owasp_id`, `mitre_attack_technique`,
`mitre_atlas_technique`, and `ai_component` fields on threats/chain steps where applicable. Then
render whichever formats the user requested:

```
python3 scripts/build_docx_report.py report_data.json <Service>_Threat_Model_Report.docx
python3 scripts/build_xlsx_report.py report_data.json <Service>_Threat_Model_Risk_Register.xlsx
```

Verify both files opened cleanly (row/heading counts are non-zero, no exceptions) before presenting.

### Step 9 — Present and summarize

Present the `.docx`/`.xlsx` (per user's chosen formats) and both `.drawio` files together. Summarize
in chat: total threats by STRIDE category, High/Medium/Low counts, OWASP/MITRE coverage highlights
(e.g. "3 OWASP LLM Top 10 categories represented, 2 MITRE ATLAS techniques tagged"), the top attack
chain and its business consequence, and the count of compliance gaps with additional controls
recommended. Keep the chat summary short — the documents carry the detail.

---

## Quality Standards

- Every STRIDE category has at least 2 threats; every threat maps to a numbered data flow. For
  AI-scoped systems, at least one threat per category is drawn from `references/ai-threat-taxonomy.md`.
- Every threat has a Likelihood/Impact/Score with an honest, varied impact rationale — not everything
  clustered at Medium.
- Every threat has an existing-compensating-controls entry (or explicit "none identified"), a
  mitigation-probability estimate, a residual risk, and at least one additional control required.
- Every threat carries at least one `owasp_id` from `references/owasp-mappings.md`.
- At least one attack chain links 2+ threats with a concrete narrative and named business
  consequence, with steps tagged against MITRE ATT&CK and/or ATLAS per `references/mitre-mappings.md`.
- Every partially-compliant control gets a specific, actionable additional control — not generic
  advice like "improve monitoring."
- Both `.drawio` files parse as valid XML and every flow/threat-actor referenced in the report also
  appears in the diagram.
- Large raw connector payloads are summarized via `scripts/summarize.py` before being read into
  context, not pasted in full.
- If full PASTA was requested, all 7 stages from `references/pasta-methodology.md` are addressed and
  the report's `methodology` field says so explicitly.

## Error Handling

| Situation | Action |
|---|---|
| A connector's env vars are missing | Name the missing variable(s), point to `README.md` / `.env.example`, continue with other available sources |
| Connector API call fails (auth/network) | Report the failure plainly, ask if the user wants to retry, proceed without that source if not |
| No sources configured at all | Ask the user to either configure a connector or paste a manual description; do not fabricate ticket/build data |
| `generate_drawio.py` or a build script errors | Fix the input spec/data and retry once; if still failing, output the underlying JSON/markdown content in chat so the user has the material even without the rendered file |
| ServiceNow not connected, no compliance data available | Derive gaps from Step 5's compensating-controls analysis instead of skipping Section 11 entirely |
| Uncertain whether an OWASP/MITRE ID is current | Say so explicitly in the report rather than guessing silently — both frameworks are revised periodically; point the user to owasp.org / genai.owasp.org / attack.mitre.org / atlas.mitre.org to confirm before a compliance-facing report is finalized |
