# PASTA — Process for Attack Simulation and Threat Analysis

`stride-methodology.md` borrows PASTA's business-impact scoring idea for speed. This reference gives
the **full 7-stage PASTA process** for engagements that need risk-management-grade rigor (compliance
audits, pre-launch gates on regulated systems, or whenever the user explicitly asks for "PASTA" by
name) rather than the lighter STRIDE-plus-scoring default. PASTA is attacker-centric and
business-risk-driven where STRIDE is DFD-centric and enumeration-driven — running both together
gives you STRIDE's completeness and PASTA's business framing.

Map each stage to the skill's existing steps so nothing is duplicated:

## Stage 1 — Define Business Objectives

**Feeds Step 1 (Scope the assessment).** Beyond "which system and which connectors," capture: what
business capability does this system deliver, what would a security failure cost the business
specifically (revenue, regulatory standing, customer trust, contractual SLA), and who are the risk
owners who need to sign off on the resulting register. Pull this from Jira epic descriptions,
ServiceNow change justifications, or ask the user directly if not available from connectors.

## Stage 2 — Define the Technical Scope

**Feeds Step 1 and Step 2 (pull context).** Enumerate the technical attack surface precisely:
network zones, hosts/services, third-party dependencies, and — for AI-scoped systems — which
AI/ML pipeline components from `ai-threat-taxonomy.md` are in scope. Be explicit about what's
out of scope (mirrors the `scope` field already in `report-data-schema.json`).

## Stage 3 — Application Decomposition (Identify Assets, Trust Boundaries, Data Flows)

**Feeds Step 3 (DFD + trust boundaries + threat actors).** This is the same artifact Step 3 already
produces — the DFD/threat-model spec and `.drawio` diagrams. No extra deliverable needed; PASTA and
STRIDE share this stage.

## Stage 4 — Threat Analysis

**Feeds Step 4 (STRIDE threat register), informed by real threat intelligence rather than only
enumeration.** Ground the register in evidence: ServiceNow's `get_compliance_gaps`/`search_table` for
prior incidents on this system, MITRE ATT&CK/ATLAS (`mitre-mappings.md`) for tactics/techniques
observed against comparable systems in the wild, and any CVEs affecting named third-party dependencies
surfaced by the repo connector. A threat with a real precedent (an actual prior incident, a known
CVE, a documented ATLAS case study) should score at least one Likelihood point higher than the same
threat class asserted from enumeration alone — this is the same rule already stated in
`stride-methodology.md`'s Likelihood table, now with an explicit intel-gathering stage behind it.

## Stage 5 — Vulnerability and Weakness Analysis

**New analysis, feeds into Step 4's threats and Step 5's compensating controls.** For each
component identified in Stage 3, explicitly check it against the relevant OWASP list from
`owasp-mappings.md` (Top 10, API Security Top 10, and/or Top 10 for LLM Applications depending on
component type) as a checklist, not just as a labeling exercise after the fact. Any OWASP category
with no corresponding threat in the register for an in-scope component is a coverage gap — either add
the threat or explicitly note why it doesn't apply to this system.

## Stage 6 — Attack Modeling / Simulation

**Feeds Step 6 (attack chain mapping).** This is the same artifact Step 6 already produces, with one
addition when running full PASTA: tag each attack-chain step with the MITRE ATT&CK or ATLAS
technique ID it corresponds to (`mitre-mappings.md`) so the chain reads as attacker tradecraft, not
just an ordered list of findings. This is what "attack simulation" means in PASTA — modeling how a
real adversary chains techniques, not just listing vulnerabilities.

## Stage 7 — Risk and Impact Analysis

**Feeds Step 5 (compensating controls/residual risk), Step 7 (compliance gaps), and Step 8 (report
build).** Roll the business objectives from Stage 1 back in: the final risk register and executive
summary should state impact in the business terms captured in Stage 1 (revenue at risk, specific
regulatory regime, contractual exposure) — not only the generic Impact-table language from
`stride-methodology.md`. This is the PASTA-specific addition to the executive summary: tie the
top attack chain's `overall_risk` explicitly back to the Stage 1 business objective it threatens.

## When to Invoke Full PASTA vs. the Lightweight Default

| Situation | Approach |
|---|---|
| Routine feature review, periodic reassessment | STRIDE + business-impact scoring (default, `stride-methodology.md`) |
| User says "PASTA", "attack simulation", or "business-risk-driven threat model" | Walk all 7 stages above explicitly, and label the report's `methodology` field accordingly |
| Compliance audit follow-up, pre-launch gate on a regulated system, board/exec-facing report | Full 7-stage PASTA — Stage 1's business framing and Stage 6's attacker tradecraft mapping are usually what a non-technical risk owner actually needs |

## Common Failure Mode to Avoid

Treating PASTA as "STRIDE with extra paperwork." The distinguishing value of PASTA is Stage 1's
business-objective framing carried all the way through to Stage 7's impact analysis, and Stage 4's
grounding in actual threat intelligence rather than pure enumeration. Skipping straight to a threat
list without stating what business objective is at risk defeats the purpose of running PASTA instead
of the lightweight default.
