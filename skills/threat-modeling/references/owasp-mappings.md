# OWASP Mapping Reference — AppSec, API, and LLM/AI Top 10s

Every threat in the register gets tagged with the applicable OWASP ID(s) in the `owasp_id` array
field (`report-data-schema.json`). Most threats map to exactly one list; a threat on an AI-exposed
API endpoint (e.g. an inference API with a broken authorization check) can legitimately carry IDs
from more than one list — tag all that apply.

**IDs below reflect each list's most recent published edition at the time this reference was
written. OWASP revises these periodically — if the user's engagement needs current-as-of-today IDs,
verify against owasp.org / genai.owasp.org before finalizing the report, and note the version used in
the report's `methodology` field.**

## Which list applies to which component

| Component type | Primary list |
|---|---|
| Traditional web/mobile app, internal service | OWASP Top 10 (2021) |
| REST/GraphQL/RPC API (including an ML inference endpoint's API surface) | OWASP API Security Top 10 (2023) |
| LLM application, RAG pipeline, agent/tool-orchestration layer | OWASP Top 10 for LLM Applications (2025) |

## OWASP Top 10 (2021) — Web Application Security

| ID | Category |
|---|---|
| A01:2021 | Broken Access Control |
| A02:2021 | Cryptographic Failures |
| A03:2021 | Injection |
| A04:2021 | Insecure Design |
| A05:2021 | Security Misconfiguration |
| A06:2021 | Vulnerable and Outdated Components |
| A07:2021 | Identification and Authentication Failures |
| A08:2021 | Software and Data Integrity Failures |
| A09:2021 | Security Logging and Monitoring Failures |
| A10:2021 | Server-Side Request Forgery (SSRF) |

## OWASP API Security Top 10 (2023)

| ID | Category |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

## OWASP Top 10 for LLM Applications (2025)

| ID | Category | Cross-reference in `ai-threat-taxonomy.md` |
|---|---|---|
| LLM01:2025 | Prompt Injection | Tampering — direct/indirect prompt injection |
| LLM02:2025 | Sensitive Information Disclosure | Information Disclosure — completion leakage |
| LLM03:2025 | Supply Chain | Base model / dataset / adapter / package provenance |
| LLM04:2025 | Data and Model Poisoning | Tampering — training data poisoning |
| LLM05:2025 | Improper Output Handling | Elevation of Privilege — insecure output handling |
| LLM06:2025 | Excessive Agency | Elevation of Privilege — over-permissioned agents |
| LLM07:2025 | System Prompt Leakage | Information Disclosure — system prompt extraction |
| LLM08:2025 | Vector and Embedding Weaknesses | Tampering — vector store / RAG poisoning |
| LLM09:2025 | Misinformation | Hallucination-driven downstream decisions |
| LLM10:2025 | Unbounded Consumption | Denial of Service — denial of wallet, resource exhaustion |

## Tagging Rules

- Every threat record gets at least one `owasp_id`. If a threat genuinely doesn't fit any list
  (rare — most security threats map to at least one), state that explicitly rather than forcing a
  tag.
- Use Stage 5 of `pasta-methodology.md` (Vulnerability and Weakness Analysis) as a checklist pass:
  for every in-scope component, walk the applicable list top to bottom and confirm each category is
  either represented by a threat or explicitly ruled out as not applicable.
- `build_docx_report.py` and `build_xlsx_report.py` render `owasp_id` as a dedicated column in the
  threat register and in the "Framework Coverage Mapping" appendix — keep IDs in the exact `A01:2021`
  / `API1:2023` / `LLM01:2025` format shown above so the report renders consistently.
