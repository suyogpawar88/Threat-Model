# Threat Model Plugin

An AI-assisted threat modeling toolkit that pulls live context from **Jira, Jenkins, ServiceNow, and
a code repository** via API-key-authenticated connectors, then runs an end-to-end security threat
model covering **conventional application/API systems and AI/ML/LLM infrastructure alike**: a data
flow diagram, a threat-model diagram (trust boundaries + threat actors), a STRIDE threat register
scored for business impact (optionally the full 7-stage PASTA process), AI/ML-specific threats
(prompt injection, training/RAG data poisoning, model extraction, excessive agency, insecure output
handling, unbounded consumption), attack-chain mapping, a compensating-controls and
mitigation-assurance assessment, and a compliance gap analysis. Every threat and attack-chain step is
mapped to **OWASP Top 10, OWASP API Security Top 10, OWASP Top 10 for LLM Applications, MITRE
ATT&CK, and MITRE ATLAS**. Delivers a **Word report**, an **Excel risk register**, and two
**draw.io-compatible diagrams** — pick the output formats you want.

Originally built as a Claude Code / Cowork plugin, this repo now also runs under **OpenAI Codex CLI**
(via `AGENTS.md`) and **Cursor** (via `.cursor/rules/` + `.cursor/mcp.json`) — see
["Using this plugin outside Claude Code"](#using-this-plugin-outside-claude-code--cowork) below.

A live documentation site for this plugin is published from `docs/` via GitHub Pages — see
[Publishing the docs site](#publishing-the-docs-site) below.

## Components

| Component | Location | Purpose |
|---|---|---|
| Skill (canonical workflow) | `skills/threat-modeling/` | Orchestrates the full workflow: scope → pull context → model → score → chain → recommend → render. Read by Claude Code/Cowork, Codex (via `AGENTS.md`), and Cursor alike. |
| STRIDE methodology | `skills/threat-modeling/references/stride-methodology.md` | Six STRIDE categories, minimum-threats rule, Likelihood x Impact scoring |
| PASTA methodology | `skills/threat-modeling/references/pasta-methodology.md` | Full 7-stage PASTA process for higher-rigor / compliance-facing engagements |
| AI/ML threat taxonomy | `skills/threat-modeling/references/ai-threat-taxonomy.md` | Threats across the AI/ML pipeline: data/training poisoning, prompt injection, model extraction, RAG/vector-store risks, excessive agency, insecure output handling, unbounded consumption |
| OWASP mapping reference | `skills/threat-modeling/references/owasp-mappings.md` | OWASP Top 10 (2021), OWASP API Security Top 10 (2023), OWASP Top 10 for LLM Applications (2025) ID tables |
| MITRE mapping reference | `skills/threat-modeling/references/mitre-mappings.md` | MITRE ATT&CK (Enterprise) and MITRE ATLAS tactic/technique tagging for attack chains |
| Attack-chain mapping | `skills/threat-modeling/references/attack-chain-mapping.md` | How to build a valid multi-step attack chain from register threats |
| Compensating controls & gaps | `skills/threat-modeling/references/compensating-controls-and-gaps.md` | Compensating controls, mitigation-probability, residual risk, compliance gaps |
| MCP server: Jira | `scripts/connectors/jira_connector.py` | `get_issue`, `search_issues`, `get_epic_children` |
| MCP server: Jenkins | `scripts/connectors/jenkins_connector.py` | `get_job`, `get_build`, `get_console_log_tail` |
| MCP server: ServiceNow | `scripts/connectors/servicenow_connector.py` | `get_record`, `search_table`, `get_compliance_gaps` |
| MCP server: Code repo | `scripts/connectors/repo_connector.py` | `get_file`, `list_tree`, `search_code`, `get_recent_commits`, `detect_ai_stack` (flags AI/ML framework usage) (GitHub by default) |
| Token-minimization helper | `scripts/summarize.py` | Compresses large connector payloads via the Anthropic API before they enter context; model is configurable |
| Diagram generator | `scripts/generate_drawio.py` | JSON spec → draw.io-compatible `.drawio` XML (DFD and threat-model modes; includes AI/ML component styles: training pipeline, model registry, vector store, inference endpoint, agent/tool layer) |
| Word report builder | `scripts/build_docx_report.py` | Structured JSON → polished `.docx` threat model report, including an OWASP/MITRE Framework Coverage Mapping appendix |
| Excel report builder | `scripts/build_xlsx_report.py` | Structured JSON → multi-sheet `.xlsx` risk register, including a Framework Mapping sheet |
| Docs site | `docs/index.html` | Static GitHub Pages site describing the plugin |
| Claude Code / Cowork plugin manifest | `.claude-plugin/plugin.json`, `.mcp.json` | Native plugin packaging |
| Cursor rule | `.cursor/rules/threat-modeling.mdc`, `.cursor/mcp.json` | Project rule + MCP config for Cursor |
| Codex CLI entry point | `AGENTS.md`, `config/codex-config.example.toml` | Instructions Codex reads automatically, plus an example MCP registration block |

## Setup

1. **Install the plugin** in Claude Code or Cowork (drag in the packaged `.plugin` file, or point
   at this repo if your client supports installing from a directory) — or, if you're using a
   different agent, see ["Using this plugin outside Claude Code"](#using-this-plugin-outside-claude-code--cowork)
   below.
2. **Configure connectors** — copy `.env.example` to `.env` and fill in credentials for whichever
   tools you use. None are mandatory; the skill works with any subset and falls back to asking for a
   manual description for anything not connected.

   | Connector | Required env vars | Where to get credentials |
   |---|---|---|
   | Jira | `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` | Atlassian account → API tokens |
   | Jenkins | `JENKINS_BASE_URL`, `JENKINS_USER`, `JENKINS_API_TOKEN` | Jenkins → User → Configure → API Token |
   | ServiceNow | `SERVICENOW_INSTANCE_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` | ServiceNow admin / dedicated service account |
   | Code repo | `REPO_PROVIDER` (default `github`), `REPO_TOKEN`, `REPO_OWNER`, `REPO_NAME` | GitHub → Settings → Developer settings → Personal access token (read-only repo scope) |
   | Model config | `ANTHROPIC_API_KEY`, `MODEL_NAME` (default `claude-sonnet-5`) | Anthropic Console |

3. **Install Python dependencies** for the bundled scripts (the MCP servers and report builders run
   as local Python processes launched by your client):

   ```
   pip install -r scripts/requirements.txt --break-system-packages
   ```

4. Confirm the connectors start cleanly:

   ```
   python3 scripts/connectors/jira_connector.py &   # should hang waiting on stdio, Ctrl-C to stop
   ```

## Usage

Once installed and configured, just ask, for example:

> "Threat model the Payment Onboarding epic PROJ-4210, pull in the repo org/onboarding-service and
> the onboarding-service Jenkins pipeline, and give me both a Word report and an Excel register."

> "Run a threat model against ServiceNow change CHG0043211 and flag anything partially compliant."

> "Threat model our AI support agent repo org/support-agent — it uses LangChain and Pinecone. Map
> every threat to the OWASP LLM Top 10 and MITRE ATLAS."

> "Run a full PASTA threat model on our fraud-scoring service ahead of the compliance audit."

The `threat-modeling` skill (see `skills/threat-modeling/SKILL.md`) handles scoping, connector calls,
AI-stack detection, diagram generation, STRIDE/PASTA scoring, attack-chain mapping,
compensating-controls assessment, OWASP/MITRE mapping, and report rendering end to end. See
`skills/threat-modeling/references/` for the full methodology and
`skills/threat-modeling/references/examples/` for worked sample input/output — `sample_*` files for
a conventional application, `sample_ai_*` files for an AI/RAG/agentic system.

### Trying it without any connectors configured

The diagram and report generators run standalone against the bundled example data:

```bash
# Conventional application example
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_DFD.drawio dfd
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_Threat_Model.drawio threat_model
python3 scripts/build_docx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Report.docx
python3 scripts/build_xlsx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Register.xlsx

# AI/RAG/agentic system example
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_ai_threat_model_spec.json AI_Support_Agent_DFD.drawio dfd
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_ai_threat_model_spec.json AI_Support_Agent_Threat_Model.drawio threat_model
python3 scripts/build_docx_report.py skills/threat-modeling/references/examples/sample_ai_report_data.json AI_Support_Agent_Report.docx
python3 scripts/build_xlsx_report.py skills/threat-modeling/references/examples/sample_ai_report_data.json AI_Support_Agent_Register.xlsx
```

Open the `.drawio` files at [app.diagrams.net](https://app.diagrams.net) or the draw.io desktop app.

## AI/ML infrastructure coverage

Beyond conventional web/API systems, this plugin threat-models AI/ML pipelines end to end:

- **Detection**: `scripts/connectors/repo_connector.py`'s `detect_ai_stack` tool scans a connected
  repo for AI/ML framework markers (LangChain, LlamaIndex, OpenAI/Anthropic/Bedrock/Vertex AI SDKs,
  transformers/torch/vLLM, Pinecone/Weaviate/Chroma/Qdrant/FAISS, MLflow/Kubeflow/SageMaker/Airflow,
  AutoGen/CrewAI/LangGraph) to decide whether AI-specific analysis applies.
- **Additional diagram components**: `scripts/generate_drawio.py` supports `training_pipeline`,
  `model_registry`, `vector_store`, `inference_endpoint`, and `agent` node types with distinct
  styling, alongside the existing `external_entity`/`process`/`data_store`/`external_system` types.
- **Threat taxonomy**: `skills/threat-modeling/references/ai-threat-taxonomy.md` extends every
  STRIDE category with AI-specific threats — training/fine-tuning data poisoning, direct and
  indirect prompt injection, RAG/vector-store poisoning, system prompt leakage, model
  extraction/theft, membership inference, unbounded consumption ("denial of wallet"), excessive
  agency, insecure output handling, and tool/plugin schema abuse.
- **Worked example**: `skills/threat-modeling/references/examples/sample_ai_threat_model_spec.json`
  and `sample_ai_report_data.json` model an AI support agent (RAG + tool-calling), including a
  prompt-injection-to-fraudulent-refund attack chain and a fine-tuning/model-registry supply-chain
  compromise chain.

## OWASP and MITRE framework mapping

Every threat in the register carries an `owasp_id` field, and every attack-chain step can carry
`mitre_attack_technique` / `mitre_atlas_technique` fields (see
`skills/threat-modeling/references/report-data-schema.json`). Both report builders render these as
dedicated columns and a "Framework Coverage Mapping" section/sheet:

- **OWASP Top 10 (2021)** — for conventional web/application components
- **OWASP API Security Top 10 (2023)** — for REST/GraphQL/RPC APIs, including ML inference endpoints
- **OWASP Top 10 for LLM Applications (2025)** — for LLM apps, RAG pipelines, and agents
- **MITRE ATT&CK (Enterprise)** — conventional infrastructure adversary tradecraft in attack chains
- **MITRE ATLAS** — AI/ML-specific adversary tradecraft in attack chains

Full ID tables and tagging rules are in `skills/threat-modeling/references/owasp-mappings.md` and
`skills/threat-modeling/references/mitre-mappings.md`. Both frameworks are revised periodically —
the reference docs flag this and point to the authoritative sources (owasp.org, genai.owasp.org,
attack.mitre.org, atlas.mitre.org) to verify current IDs before finalizing a compliance-facing
report.

## PASTA (full 7-stage process)

`skills/threat-modeling/references/stride-methodology.md`'s default scoring already borrows PASTA's
business-impact framing. For engagements that need the complete process — compliance audits,
pre-launch gates on regulated systems, board/exec-facing reports — ask for "PASTA" or a
"business-risk-driven threat model" explicitly; the skill will walk all 7 stages per
`skills/threat-modeling/references/pasta-methodology.md` and label the report's `methodology` field
accordingly.

## Using this plugin outside Claude Code / Cowork

The skill instructions, reference docs, JSON schemas, and Python scripts have no Claude-specific
dependencies — the same workflow runs under other coding agents:

### Cursor

1. This repo's `.cursor/rules/threat-modeling.mdc` is a Cursor project rule that points at
   `skills/threat-modeling/SKILL.md` and its `references/`. It activates automatically when Cursor's
   agent judges it relevant (or trigger it manually), since `alwaysApply` is `false`.
2. Enable the four connectors via `.cursor/mcp.json` in Cursor's MCP settings, and set the
   referenced environment variables (same ones as `.env.example`).
3. Ask Cursor's agent the same kind of prompts shown in [Usage](#usage) above.

### OpenAI Codex CLI

1. Codex reads `AGENTS.md` at the repo root automatically before doing any work — it's the
   agent-agnostic entry point into the same `skills/threat-modeling/` instructions.
2. Register the four MCP connectors in `~/.codex/config.toml` (or a trusted project-scoped
   `.codex/config.toml`) — see `config/codex-config.example.toml` for a ready-to-paste
   `[mcp_servers.*]` block, and run `codex mcp add` or edit the TOML directly. Check `codex mcp
   --help` / the Codex CLI docs for the current CLI syntax, since MCP configuration in Codex has
   changed before.
3. Run `codex` in this repo and ask for a threat model the same way you would in Claude Code.

## Model configuration (token minimization)

`scripts/summarize.py` compresses large raw connector payloads (Jenkins console logs, big Jira
threads, large repo files) via a single Anthropic API call before they're added to the main
session's context — this is the mechanism behind "uses Claude Sonnet to minimize token usage." It
defaults to `claude-sonnet-5`. To point it at a different model, set `MODEL_NAME` in `.env` (see
`config/model-config.example.json` for the available options and when you'd want each one). This
setting only affects the summarization helper; the main threat-modeling reasoning always runs on
whichever model is driving your current session.

## Extending the code-repo connector

`scripts/connectors/repo_connector.py` ships with GitHub REST API support. The tool signatures
(`get_file`, `list_tree`, `search_code`, `get_recent_commits`, `detect_ai_stack`) map cleanly onto
GitLab and Bitbucket's REST APIs — to add one, implement the equivalent request in
`_api()`/`_headers()` and set `REPO_PROVIDER` accordingly; the skill and report format don't need to
change. To track new AI/ML frameworks as they emerge, add markers to `AI_STACK_MARKERS` in the same
file.

## Publishing the docs site

This repo's `docs/` folder is a self-contained static site (no build step) intended for GitHub
Pages:

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to "Deploy from a branch," branch `main`, folder
   `/docs`.
4. Save — GitHub publishes the page at `https://<your-username>.github.io/Threat-Model/`
   within a few minutes.

## Security notes

- All connector credentials are read from environment variables, never hardcoded — see
  `.env.example`.
- All four connectors are **read-only** by design (no write/mutate tools exposed) — this plugin
  observes your systems, it doesn't change them. `detect_ai_stack` is also read-only; it only calls
  the existing `search_code` tool with a fixed marker list.
- Use least-privilege tokens: a Jira/ServiceNow account with read-only access, and a repo PAT scoped
  to read-only repo access, are sufficient for every tool in this plugin.
- Treat generated Word/Excel reports and `.drawio` files as containing sensitive architecture and
  risk information — handle distribution accordingly. This applies with extra weight to AI-scoped
  reports, which may document system prompts, tool schemas, and model deployment details.

## License

MIT
