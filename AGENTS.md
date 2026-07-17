# AGENTS.md — Threat Modeling Repo

This file is read automatically by AGENTS.md-compliant coding agents (OpenAI Codex CLI, and others
that follow the same convention). It's the agent-agnostic entry point into the same workflow that's
packaged as a Claude Code / Cowork plugin (`.claude-plugin/`) and as Cursor project rules
(`.cursor/rules/threat-modeling.mdc`) elsewhere in this repo — all three point at the same
`skills/threat-modeling/` instructions and scripts, so behavior is consistent regardless of which
agent is driving.

## What this repo does

Runs an end-to-end security threat model for a service or system — conventional application/API
infrastructure and AI/ML/LLM infrastructure alike — pulling live context from Jira, Jenkins,
ServiceNow, and a code repository, then producing:

- A STRIDE threat register scored for likelihood and business impact (optionally the full 7-stage
  PASTA process for higher-rigor engagements)
- AI/ML-specific threats (prompt injection, training/RAG data poisoning, model extraction,
  excessive agency, insecure output handling, unbounded consumption) when the system has AI/ML
  components
- Every threat mapped to OWASP Top 10 (2021), OWASP API Security Top 10 (2023), and/or OWASP Top 10
  for LLM Applications (2025)
- Attack-chain mapping with MITRE ATT&CK (Enterprise) and MITRE ATLAS technique tagging
- Compensating-controls, mitigation-assurance, and compliance-gap analysis
- A draw.io-compatible DFD, a draw.io-compatible threat-model diagram, a Word report, and/or an
  Excel risk register

## Before doing anything: read the skill

Read `skills/threat-modeling/SKILL.md` in full and follow its 9 steps in order. It is the canonical,
tool-agnostic instruction set — do not shortcut to writing a threat list without walking Steps 1-3
(scoping, context pull, DFD/trust-boundary modeling) first. Its `references/` directory has the full
methodology detail:

| Reference | Covers |
|---|---|
| `references/stride-methodology.md` | The six STRIDE categories, minimum-threats rule, Likelihood x Impact scoring |
| `references/pasta-methodology.md` | Full 7-stage PASTA process for higher-rigor engagements |
| `references/ai-threat-taxonomy.md` | AI/ML/LLM pipeline threats layered onto STRIDE |
| `references/owasp-mappings.md` | OWASP Top 10 / API Security Top 10 / LLM Top 10 ID tables |
| `references/mitre-mappings.md` | MITRE ATT&CK and ATLAS tactic/technique tagging |
| `references/attack-chain-mapping.md` | How to build a valid multi-step attack chain |
| `references/compensating-controls-and-gaps.md` | Compensating controls, residual risk, compliance gaps |
| `references/report-data-schema.json` | The JSON shape the report-builder scripts consume |
| `references/examples/` | Worked examples: `sample_*` (conventional app), `sample_ai_*` (AI/RAG/agent system) |

## Environment setup

```bash
pip install -r scripts/requirements.txt --break-system-packages
cp .env.example .env   # fill in only the connectors you plan to use; none are mandatory
```

## Registering the MCP connectors for Codex CLI

This repo's four connectors (Jira, Jenkins, ServiceNow, code repo) are plain stdio MCP servers —
register them in `~/.codex/config.toml` (or a trusted project-scoped `.codex/config.toml`) using
`codex mcp add`, or by editing the TOML directly. See `config/codex-config.example.toml` in this
repo for a ready-to-paste block, and `codex mcp --help` / the Codex CLI docs for the current CLI
syntax. `.env` values in this repo are for local script runs (`scripts/summarize.py`,
`scripts/build_*.py`); Codex's MCP server env vars are configured separately inside `config.toml`
per the example file.

## Running the standalone scripts (no connectors required)

```bash
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_DFD.drawio dfd
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_Threat_Model.drawio threat_model
python3 scripts/build_docx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Report.docx
python3 scripts/build_xlsx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Register.xlsx
```

Swap in `sample_ai_threat_model_spec.json` / `sample_ai_report_data.json` for the AI/RAG/agent
worked example.

## Conventions to follow when generating a report

- Every STRIDE category needs at least 2 threats; every threat maps to a numbered data flow.
- Every threat carries at least one `owasp_id` (`references/owasp-mappings.md`).
- Use `scripts/connectors/repo_connector.py`'s `detect_ai_stack` tool (or a manual code scan for
  LangChain/transformers/vector-DB/MLflow-style imports) to decide whether
  `references/ai-threat-taxonomy.md` applies.
- At least one attack chain links 2+ threats with steps tagged against MITRE ATT&CK and/or ATLAS
  (`references/mitre-mappings.md`).
- Pipe large connector payloads through `scripts/summarize.py --focus "..."` before reading them in
  full (requires `ANTHROPIC_API_KEY`).
- Never fabricate ticket/build/compliance data — if a source isn't connected, say so and proceed
  with what's available, or ask the user for a manual description.
