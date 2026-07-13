# AppSec Threat Modeler

A Claude plugin that pulls live context from **Jira, Jenkins, ServiceNow, and a code repository**
via API-key-authenticated connectors, then runs an end-to-end security threat model: a data flow
diagram, a threat-model diagram (trust boundaries + threat actors), a STRIDE threat register scored
for business impact, attack-chain mapping, a compensating-controls and mitigation-assurance
assessment, and a compliance gap analysis with additional controls recommended for anything found
partially compliant. Delivers a **Word report**, an **Excel risk register**, and two
**draw.io-compatible diagrams** — pick the output formats you want.

A live documentation site for this plugin is published from `docs/` via GitHub Pages — see
[Publishing the docs site](#publishing-the-docs-site) below.

## Components

| Component | Location | Purpose |
|---|---|---|
| Skill | `skills/threat-modeling/` | Orchestrates the full workflow: scope → pull context → model → score → chain → recommend → render |
| MCP server: Jira | `scripts/connectors/jira_connector.py` | `get_issue`, `search_issues`, `get_epic_children` |
| MCP server: Jenkins | `scripts/connectors/jenkins_connector.py` | `get_job`, `get_build`, `get_console_log_tail` |
| MCP server: ServiceNow | `scripts/connectors/servicenow_connector.py` | `get_record`, `search_table`, `get_compliance_gaps` |
| MCP server: Code repo | `scripts/connectors/repo_connector.py` | `get_file`, `list_tree`, `search_code`, `get_recent_commits` (GitHub by default) |
| Token-minimization helper | `scripts/summarize.py` | Compresses large connector payloads via the Anthropic API before they enter context; model is configurable |
| Diagram generator | `scripts/generate_drawio.py` | JSON spec → draw.io-compatible `.drawio` XML (DFD and threat-model modes) |
| Word report builder | `scripts/build_docx_report.py` | Structured JSON → polished `.docx` threat model report |
| Excel report builder | `scripts/build_xlsx_report.py` | Structured JSON → multi-sheet `.xlsx` risk register |
| Docs site | `docs/index.html` | Static GitHub Pages site describing the plugin |

## Setup

1. **Install the plugin** in Claude Code or Cowork (drag in the packaged `.plugin` file, or point
   at this repo if your client supports installing from a directory).
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
   as local Python processes launched by your Claude client):

   ```
   pip install mcp requests python-docx openpyxl anthropic --break-system-packages
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

The `threat-modeling` skill (see `skills/threat-modeling/SKILL.md`) handles scoping, connector calls,
diagram generation, STRIDE scoring, attack-chain mapping, compensating-controls assessment, and
report rendering end to end. See `skills/threat-modeling/references/` for the full methodology and
`skills/threat-modeling/references/examples/` for worked sample input/output.

### Trying it without any connectors configured

The diagram and report generators run standalone against the bundled example data:

```bash
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_DFD.drawio dfd
python3 scripts/generate_drawio.py skills/threat-modeling/references/examples/sample_threat_model_spec.json Sample_Threat_Model.drawio threat_model
python3 scripts/build_docx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Report.docx
python3 scripts/build_xlsx_report.py skills/threat-modeling/references/examples/sample_report_data.json Sample_Register.xlsx
```

Open the `.drawio` files at [app.diagrams.net](https://app.diagrams.net) or the draw.io desktop app.

## Model configuration (token minimization)

`scripts/summarize.py` compresses large raw connector payloads (Jenkins console logs, big Jira
threads, large repo files) via a single Anthropic API call before they're added to the main
session's context — this is the mechanism behind "uses Claude Sonnet to minimize token usage." It
defaults to `claude-sonnet-5`. To point it at a different model, set `MODEL_NAME` in `.env` (see
`config/model-config.example.json` for the available options and when you'd want each one). This
setting only affects the summarization helper; the main threat-modeling reasoning always runs on
whichever model is driving your current Claude session.

## Extending the code-repo connector

`scripts/connectors/repo_connector.py` ships with GitHub REST API support. The tool signatures
(`get_file`, `list_tree`, `search_code`, `get_recent_commits`) map cleanly onto GitLab and Bitbucket's
REST APIs — to add one, implement the equivalent request in `_api()`/`_headers()` and set
`REPO_PROVIDER` accordingly; the skill and report format don't need to change.

## Publishing the docs site

This repo's `docs/` folder is a self-contained static site (no build step) intended for GitHub
Pages:

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to "Deploy from a branch," branch `main`, folder
   `/docs`.
4. Save — GitHub publishes the page at `https://<your-username>.github.io/appsec-threat-modeler/`
   within a few minutes.

## Security notes

- All connector credentials are read from environment variables, never hardcoded — see
  `.env.example`.
- All four connectors are **read-only** by design (no write/mutate tools exposed) — this plugin
  observes your systems, it doesn't change them.
- Use least-privilege tokens: a Jira/ServiceNow account with read-only access, and a repo PAT scoped
  to read-only repo access, are sufficient for every tool in this plugin.
- Treat generated Word/Excel reports and `.drawio` files as containing sensitive architecture and
  risk information — handle distribution accordingly.

## License

MIT
