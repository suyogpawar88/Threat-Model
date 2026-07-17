# MITRE ATT&CK and MITRE ATLAS Mapping Reference

Full detail for tagging attack-chain steps (Step 6 / PASTA Stage 6) with real adversary tradecraft
identifiers instead of only free-text descriptions. Two frameworks, two attack surfaces:

- **MITRE ATT&CK (Enterprise)** — general IT infrastructure tradecraft. Use for chain steps
  involving conventional infrastructure: credential theft, lateral movement, CI/CD compromise,
  exfiltration over standard channels.
- **MITRE ATLAS** — adversarial tradecraft specifically against AI/ML systems. Use for chain steps
  involving any component from `ai-threat-taxonomy.md` (training pipeline, model registry, vector
  store, inference endpoint, agent/tool layer).

**IDs below are commonly cited, stable identifiers useful as a starting reference. Both frameworks
are living knowledge bases that add techniques over time — verify current IDs/wording against
attack.mitre.org and atlas.mitre.org before finalizing a report, especially for ATLAS which is
younger and revised more frequently.**

## MITRE ATT&CK (Enterprise) — Tactics

| Tactic | Typical relevance to this plugin's attack chains |
|---|---|
| Reconnaissance | Recon of exposed endpoints/repos before an attack chain begins |
| Resource Development | Attacker infrastructure/tooling setup (rarely modeled explicitly, note if relevant) |
| Initial Access | The chain's starting threat — e.g. `S-1` session replay, a public-facing app exploit |
| Execution | Running attacker-controlled code (e.g. via an insecure deserialization or debug endpoint threat) |
| Persistence | Maintaining access — a planted backdoor, a modified CI/CD credential |
| Privilege Escalation | Elevation-of-Privilege category threats — parameter tampering, debug endpoints |
| Defense Evasion | Missing/mutable audit logs (Repudiation threats) that let a chain go undetected |
| Credential Access | Compromised CI/CD credentials, captured session tokens |
| Discovery | Attacker enumerating internal services/data stores after initial access |
| Lateral Movement | Moving from one compromised component to another (e.g. gateway → internal service) |
| Collection | Gathering data prior to exfiltration (e.g. staging PII before transfer) |
| Command and Control | Attacker-controlled channel back to compromised infrastructure |
| Exfiltration | Information Disclosure threats reaching completion — data actually leaving the boundary |
| Impact | The chain's final business consequence — fraud, service disruption, unauthorized approval |

Example: the sample threat model's `AC-1` chain (session replay → parameter tampering → undetected
approval) maps to **Initial Access** (captured/replayed session token) → **Privilege Escalation**
(status parameter tampering) → **Defense Evasion** (no immutable audit log, so the bypass isn't
caught) → **Impact** (sanctioned applicant approved).

## MITRE ATLAS — Tactics

ATLAS mirrors ATT&CK's structure with AI-specific tactics, including (non-exhaustive — confirm full,
current list at atlas.mitre.org): Reconnaissance (`AML.TA0002`), Resource Development
(`AML.TA0003`), Initial Access (`AML.TA0004`), ML Model Access (`AML.TA0000`), Execution
(`AML.TA0005`), Persistence (`AML.TA0006`), Privilege Escalation (`AML.TA0012`), Defense Evasion
(`AML.TA0007`), Credential Access (`AML.TA0008`), Discovery, Collection, ML Attack Staging,
Exfiltration, and Impact.

## MITRE ATLAS — Frequently-Cited Techniques for This Plugin's AI Threat Taxonomy

| ATLAS Technique | Name | Corresponds to (`ai-threat-taxonomy.md`) |
|---|---|---|
| `AML.T0051` | LLM Prompt Injection | Direct/indirect prompt injection (Tampering) |
| `AML.T0020` | Poison Training Data | Training/fine-tuning data poisoning (Tampering) |
| `AML.T0024` | Exfiltration via ML Inference API | Model extraction/theft (Information Disclosure) |
| `AML.T0053` | LLM Plugin Compromise | Tool/plugin schema abuse, excessive agency (Elevation of Privilege) |
| `AML.T0018` | Manipulate AI Model (backdoor/trojan) | Model artifact tampering via CI/CD or registry (Tampering) |
| `AML.T0040` | ML Model Inference API Access | Precondition step for model extraction / membership inference chains |

## Tagging Rules for Attack Chains

For each `steps[]` entry in an attack chain (`report-data-schema.json`), add:
- `mitre_attack_technique`: array of ATT&CK technique IDs (e.g. `["T1078"]` for valid accounts used
  in a credential-replay step), when the step involves conventional infrastructure tradecraft.
- `mitre_atlas_technique`: array of ATLAS technique IDs (e.g. `["AML.T0051"]`), when the step
  involves an AI/ML component.

A single step can carry both if it spans an AI component reached through conventional
infrastructure (e.g. a compromised CI/CD credential used to push a poisoned model into the
registry: ATT&CK `T1078`/`T1195` for the CI/CD compromise, ATLAS `AML.T0018` for the model
manipulation itself).

## Common Failure Mode to Avoid

Forcing an ATLAS ID onto a step that is really just conventional infrastructure compromise (e.g.
a stolen cloud credential with no AI-specific tradecraft involved) — that step belongs to ATT&CK
only. Reserve ATLAS tags for steps where the *target or technique* is genuinely AI/ML-specific, not
just "this system happens to have a model somewhere in it."
