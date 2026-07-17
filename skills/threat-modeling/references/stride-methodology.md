# STRIDE Methodology with Business-Impact Scoring

Full detail for Step 4 of `SKILL.md`. STRIDE is the enumeration engine — fast and automatable
because it works directly off the DFD, checking every data flow and trust boundary crossing against
the same six categories. The scoring layer below borrows PASTA's most valuable idea — tying each
threat to actual business impact — without needing PASTA's full 7-stage live-intel process.

## The Six Categories

| Category | Code | What to look for |
|---|---|---|
| **Spoofing** | S | Identity impersonation — fake users, replayed tokens, forged API keys, credential stuffing |
| **Tampering** | T | Data modification in transit or at rest — MitM, unsigned internal calls, forged build artifacts |
| **Repudiation** | R | Denial of actions — missing/mutable audit logs, unsigned transactions, unverifiable approvals |
| **Information Disclosure** | I | Data leakage — exposed PII, verbose errors, unencrypted fields, over-broad third-party transfers |
| **Denial of Service** | D | Availability attacks — missing rate limits, resource exhaustion, retry storms |
| **Elevation of Privilege** | E | Access escalation — client-controlled state, debug endpoints, over-scoped credentials, cross-tenant access |

## Threat Register Rules

- Minimum 2 threats per category (12+ total for anything beyond a trivial system).
- Every threat ties to a specific numbered data flow from the DFD.
- Threat IDs follow `S-1`, `S-2`, `T-1`, `E-1`, etc.
- Every threat names a specific threat actor (not just "an attacker") — reuse the threat actors
  placed on the threat-model diagram in Step 3.
- Every mitigation is specific and actionable ("bind session to device fingerprint with a 15-minute
  TTL," not "improve session security").

## Likelihood (1–5)

| Score | Meaning |
|---|---|
| 5 | Exploitable today with public tools/knowledge, no special access needed |
| 4 | Exploitable with moderate effort or a common attacker position (e.g. network MitM) |
| 3 | Requires specific conditions (race window, misconfigured flag) |
| 2 | Requires privileged access or an insider position |
| 1 | Theoretical — no known practical exploitation path |

If ServiceNow incident history is available for this system, use it to ground Likelihood — a threat
class with a real prior incident should score at least a point higher than the same threat class with
no history.

## Business Impact (1–5)

Score the **highest** applicable factor; don't average across factors.

| Score | Data sensitivity | Compliance exposure | Blast radius | Reputational impact |
|---|---|---|---|---|
| 5 | Full PII/financial/credential sets exposed | Reportable breach under a named regulatory regime; licence risk | Cross-tenant, affects all customers | Public disclosure likely, regulator scrutiny |
| 4 | Partial PII or financial data exposed | Violation requiring a remediation plan, not immediately reportable | Multiple customers/one segment | Customer-visible incident |
| 3 | Internal operational data, non-financial tokens | Audit finding, no external reporting trigger | Single tenant, contained | Internal/partner-visible only |
| 2 | Non-sensitive metadata | No compliance angle | Single session/transaction | No external visibility |
| 1 | No meaningful data exposure | None | Negligible | None |

Name the regulatory regime explicitly when it's identifiable from the source material (e.g. a
specific data-protection law, PCI-DSS, a named licensing authority) rather than defaulting to a
generic "compliance risk."

## Risk Score

`Score = Likelihood × Impact` (range 1–25). Bucket for readability:

- 🔴 **High**: 15–25
- 🟡 **Medium**: 6–14
- 🟢 **Low**: 1–5

Record every threat as `L×I=Score` (e.g. `4×5=20`) so the reasoning is visible, not just the label.
Every 4-or-5 impact score must name the specific driver (which factor in the table above drove it).

## Common Failure Mode to Avoid

Clustering everything at Medium to avoid a hard conversation. A register that inflates every threat
to High is as useless as one that calls everything fine. Use the full 1–5 range on both dimensions,
and let the score — not gut feel — drive the final Risk Prioritization ordering in the report.

## Applying STRIDE to AI/ML and LLM Components

If Step 1 scoping identifies any AI/ML pipeline component (training/fine-tuning, model registry,
vector store/RAG, inference endpoint, agent/tool-orchestration layer) — or `repo_connector.py`'s
`detect_ai_stack` tool flags AI framework usage in the repo — walk `ai-threat-taxonomy.md` in full
alongside this file. It extends each of the six categories above with AI-specific threats (prompt
injection, training data poisoning, model extraction, excessive agency, etc.), each pre-mapped to an
OWASP Top 10 for LLM Applications ID and, where relevant, a MITRE ATLAS technique. The
minimum-2-threats-per-category rule still applies; for an AI-scoped system, at least one threat per
category should come from the AI-specific list rather than only the generic web-app equivalents.

For engagements that need full business-risk-driven rigor (compliance audits, pre-launch gates on
regulated AI systems) rather than this lightweight scoring layer, see `pasta-methodology.md` for the
complete 7-stage PASTA process, which this file's scoring approach is intentionally a lightweight
subset of.
