# AI / ML Infrastructure Threat Taxonomy

Extends `stride-methodology.md` to systems that include AI/ML/LLM components. Use this reference
whenever Step 1 scoping identifies any of: a model training or fine-tuning pipeline, a model
registry, a vector store / RAG pipeline, an LLM or ML inference endpoint, an agent/tool-calling
orchestration layer, or an MLOps CI/CD pipeline that builds/deploys models. `scripts/connectors/repo_connector.py`'s
`detect_ai_stack` tool can flag these automatically from repo code (langchain, transformers, torch,
pinecone/weaviate/chroma, vLLM, MLflow, SageMaker/Vertex AI/Bedrock imports, etc.) — treat a positive
hit as a signal to walk this reference in full, not just standard STRIDE.

STRIDE stays the enumeration engine — every AI-specific threat below still maps to one of the six
categories. What changes is *where* to look: the AI/ML pipeline introduces components and data flows
that a generic web-app DFD doesn't have, and those components have their own attacker-relevant
failure modes.

## The AI/ML Pipeline as Additional DFD Components

Add these component types to Step 3's DFD/threat-model diagram wherever they exist in the system
being modeled (see `generate_drawio.py`'s `training_pipeline`, `model_registry`, `vector_store`,
`inference_endpoint`, and `agent` node styles):

| Component | Typical role | Trust boundary usually crossed |
|---|---|---|
| Data collection / labeling pipeline | Ingests training/fine-tuning data, often from external or crowdsourced sources | External data source → internal training environment |
| Training / fine-tuning pipeline | Produces model weights from training data + base model | Training environment → model registry |
| Model registry | Stores/versions trained model artifacts | Registry → serving infrastructure |
| Vector store / embedding index | Backs RAG retrieval; stores embeddings of internal documents | Ingestion pipeline → retrieval → LLM context |
| Inference / serving endpoint | Runs the model against live requests (self-hosted or third-party API) | External/internal caller → model |
| Agent / tool-orchestration layer | Lets an LLM call tools, browse, execute code, or take actions | LLM output → real-world side effects |
| MLOps CI/CD | Builds containers, pushes model artifacts, manages GPU infra-as-code | Same risk class as regular CI/CD (see `T-2` pattern in the sample threat model), amplified because compromise can mean silent model substitution |

## AI-Specific Threats by STRIDE Category

Minimum-threats rule from `stride-methodology.md` still applies (2+ per category). When AI/ML
components are in scope, make sure at least one threat per category below is drawn from this table
rather than relying only on generic web-app equivalents.

### Spoofing

- Impersonating a legitimate model API consumer to exhaust a rate-limited/paid inference endpoint.
- Spoofed system-prompt or role-tag injection making the model treat attacker content as a trusted
  instruction source (a precursor to prompt injection, see Tampering).
- Forged/replayed tool-call responses fed back into an agent's context to redirect its next action.

### Tampering

- **Training/fine-tuning data poisoning** — an attacker with write access to a training corpus (or a
  scraped/crowdsourced source) inserts mislabeled or adversarial examples to bias model behavior or
  plant a backdoor trigger. Maps to OWASP LLM04:2025 (Data and Model Poisoning) and MITRE ATLAS
  `AML.T0020` (Poison Training Data).
- **Direct prompt injection** — attacker-supplied input overrides system instructions. Maps to OWASP
  LLM01:2025 and MITRE ATLAS `AML.T0051` (LLM Prompt Injection).
- **Indirect prompt injection** — malicious instructions embedded in a document, webpage, email, or
  tool result that the model later retrieves and treats as trusted content (RAG pipelines and
  browsing/tool-using agents are the primary exposure). Same OWASP/ATLAS mapping as direct injection,
  but the entry point is a data flow rather than the user's own input, so it needs its own row in the
  register and its own numbered data flow.
- **Vector store poisoning** — attacker-controlled documents inserted into an ingestion pipeline feed
  the RAG index, surfacing attacker content as if it were trusted knowledge base material. Maps to
  OWASP LLM08:2025 (Vector and Embedding Weaknesses).
- **Model artifact tampering in the registry or CI/CD pipeline** — same class as `T-2` in the sample
  threat model (unscoped deploy credential), but the blast radius is a silently substituted model
  rather than a substituted application binary; harder to detect without artifact signing.

### Repudiation

- No immutable log of prompts, completions, retrieved context, and tool calls, making it impossible
  to reconstruct why an agent took a given action after an incident.
- No record of which model/weights version served a given inference, preventing root-cause analysis
  after a bad output is reported (was it prompt injection, model drift, or a bad fine-tune?).

### Information Disclosure

- **Sensitive information disclosure via completions** — the model reveals PII, secrets, or
  proprietary content memorized during training or present in retrieved RAG context. Maps to OWASP
  LLM02:2025.
- **System prompt leakage** — an attacker extracts the system prompt (which may itself contain
  business logic, credentials, or internal tool schemas) via direct questioning or adversarial
  prompting. Maps to OWASP LLM07:2025.
- **Model extraction / theft** — repeated, systematic querying reconstructs a functionally equivalent
  copy of a proprietary model, or exfiltrates fine-tuned weights via an over-permissioned registry
  credential. Maps to MITRE ATLAS `AML.T0024` (Exfiltration via ML Inference API) and its sibling
  extraction techniques.
- **Membership inference** — an attacker determines whether a specific record was part of the
  training set, a privacy/compliance concern for any model trained on regulated data.

### Denial of Service

- **Unbounded consumption / "denial of wallet"** — no limits on prompt length, output length,
  recursive agent loop depth, or per-user/per-key request volume, allowing cost exhaustion or
  resource-starvation attacks against a metered inference API. Maps to OWASP LLM10:2025.
- Adversarial inputs crafted to maximize inference latency/compute (e.g. pathological input lengths
  or recursive tool-call loops in an agent).

### Elevation of Privilege

- **Excessive agency** — an agent is granted broader tool permissions, autonomy, or approval
  authority than its actual task requires (e.g. an LLM-backed support agent that can issue refunds
  without human sign-off). Maps to OWASP LLM06:2025 and MITRE ATLAS `AML.T0053`
  (LLM Plugin Compromise) where the excess agency is exposed through a tool/plugin.
- **Insecure output handling** — a model's output is passed to a downstream interpreter (shell,
  SQL, HTML renderer, code-exec sandbox) without the same input validation/escaping a human-submitted
  value would get, turning a successful prompt injection into code execution or an XSS/SQLi
  equivalent. Maps to OWASP LLM05:2025.
- **Tool/plugin schema abuse** — a tool description or parameter schema is manipulated (via prompt
  injection or a compromised tool registry) to make the agent call a more privileged tool than the
  user's request warrants.

## Additional AI-Specific Categories Not Cleanly STRIDE-Shaped

Record these as their own threats even though they sit slightly outside classic STRIDE — put them in
the category they most affect (usually Information Disclosure or Tampering) and note the deviation in
the threat description:

- **Misinformation / hallucination-driven decisions** (OWASP LLM09:2025) — the model produces
  confident, incorrect output that a downstream process or human treats as ground truth (e.g. a
  hallucinated compliance citation, a fabricated API response schema an agent then acts on).
- **Supply chain** (OWASP LLM03:2025) — a compromised or unvetted third-party base model, fine-tuning
  dataset, LoRA adapter, embedding model, or ML package (PyPI/conda typosquat targeting
  `transformers`/`torch`/etc.) introduced anywhere in the pipeline.

## Quality Standard for AI-Scoped Systems

When AI/ML components are in scope, every threat drawn from this taxonomy must additionally carry:
`owasp_id` (the OWASP LLM Top 10 ID, and OWASP API/AppSec IDs where the flow also crosses a
traditional API/web boundary) and, where an attack-chain step represents adversary tradecraft against
the model itself, `mitre_atlas_id` — see `owasp-mappings.md` and `mitre-mappings.md` for the full
mapping tables and how these fields populate `report-data-schema.json`.
