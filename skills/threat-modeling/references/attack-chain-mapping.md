# Attack Chain / Attack Scenario Mapping

Full detail for Step 6 of `SKILL.md`. An itemized STRIDE register tells a reviewer what's wrong; an
attack chain tells them what actually happens if two or three of those things are exploited together
in sequence — which is usually the more persuasive, more actionable artifact for a risk owner or a
pre-launch sign-off.

## What Makes a Real Attack Chain (Not Just a List)

A valid attack chain:
1. **Starts from a plausible initial position** — usually the threat actor with the lowest privilege
   bar (unauthenticated external attacker is the default starting point unless the scenario is
   explicitly insider-driven).
2. **Links 2 or more threats from the register in sequence**, where completing one step is what makes
   the next step possible or more effective. Steps should reference real threat IDs already in the
   register — do not invent a new threat solely for the chain.
3. **Ends in a concrete business consequence** — not "the attacker gains access" but "the attacker
   can approve a sanctioned applicant without detection," or "the attacker obtains full production
   host access via CI/CD."
4. **Names why detection would fail or succeed at each step** where relevant — a chain that would be
   caught immediately by existing monitoring is lower priority than one that would go undetected.

## Fields to Capture Per Chain

| Field | Content |
|---|---|
| `chain_id` | `AC-1`, `AC-2`, etc. |
| `name` | Short, specific label naming the outcome (e.g. "Sanctioned applicant self-approval via session replay + parameter tampering") |
| `narrative` | 2–4 sentence prose walkthrough of the full chain, written so a non-technical risk owner can follow it |
| `steps` | Ordered list of `{step_num, threat_id, description}` — description explains what happens at this specific step, not a restatement of the threat title |
| `overall_risk` | A risk statement in prose, naming the consequence and any mitigating precondition (e.g. "requires credential compromise as a precondition, but blast radius is full production access") |

## How Many Chains

Produce at least one attack chain for any system with 2+ High-risk threats that share a plausible
sequencing relationship. Systems with only Medium/Low threats can still get a chain if a realistic
combination exists (e.g. a Medium-likelihood credential issue feeding into a Medium-impact
persistence mechanism can combine into a chain worth flagging even though neither threat alone is
High). Don't force a chain that isn't real — a flat list of unrelated Low-risk threats does not need
one.

## Common Failure Mode to Avoid

Writing a chain that's really just one threat restated three times with cosmetic step labels. Each
step must represent genuinely different action/threat, and the narrative must explain the causal link
between steps ("because X succeeded, Y becomes possible"), not just list them in sequence.
