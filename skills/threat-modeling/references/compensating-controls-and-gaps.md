# Compensating Controls, Mitigation Assurance, and Compliance Gaps

Full detail for Steps 5 and 7 of `SKILL.md`. A risk score and a one-line mitigation aren't enough for
an operational risk register — a reviewer also needs to know what's already reducing the risk today,
how confident they should be that the recommended fix actually closes the gap, and what's still
needed for full closure. Skipping this turns a threat model into a document nobody can act on.

## Per-Threat Fields (Step 5)

For **every threat** in the register, add:

**Existing Compensating Controls** — what's already in place today, independent of the primary
mitigation, that reduces likelihood or impact. Look for: existing approval gates, scoping/permission
restrictions, monitoring that at least makes the issue observable after the fact, or design choices
that narrow blast radius even if not built for this specific threat. If genuinely nothing exists,
write "No compensating control identified" — an honest gap is more useful than a padded one.

**Probability of Successful Mitigation** — once the primary mitigation is implemented, how likely is
it to actually close the gap? Percentage with a one-line rationale:
- **80–95%**: standard, well-solved pattern (allow-listing, signature verification, encryption at
  rest, scoped service accounts) — low implementation risk.
- **50–75%**: meaningfully reduces risk but the underlying attack class doesn't have a complete
  technical solution (e.g. social engineering, third-party vendor risk outside direct control) —
  residual exposure is structural, not a sign of a poorly designed fix.
- **Below 50%**: flag explicitly and explain why — usually because the fix depends on a larger
  cross-cutting item not yet built (e.g. "depends on the platform migration landing first").

Vary this honestly per threat — don't default every threat to the same number.

**Residual Risk After Mitigation** — re-score Likelihood × Impact assuming the primary mitigation
*and* existing compensating controls are both in effect. Usually lower than the original score,
sometimes only slightly (a threat that's structurally hard to fully close may stay Medium even after
a good mitigation). Bucket the same way as the main scoring (🔴/🟡/🟢).

**Additional Controls Required for Complete Mitigation** — anything beyond the primary mitigation
needed to close the remaining gap: defense-in-depth layers, monitoring/alerting to catch what
prevention misses, process controls (secondary review, escalation paths), or larger initiatives the
primary fix depends on. This is the next-steps backlog a security team would write for themselves.

## Compliance Gap Analysis (Step 7)

A "partially compliant" observation is different from a threat — it's a statement about an existing
control that is implemented but incomplete, discovered either from a real compliance record (e.g. a
ServiceNow GRC table) or inferred from the compensating-controls analysis above.

For every partially compliant control, record:

| Field | What goes here |
|---|---|
| **Control** | Name/ID of the control (from ServiceNow GRC record if available, otherwise a descriptive name) |
| **Compliance Status** | Always "Partially Compliant" for entries in this section — fully compliant or fully missing controls belong elsewhere |
| **Gap Description** | The specific shortfall — not "needs improvement" but "full applicant records are transferred instead of only the fields required for screening" |
| **Recommended Additional Controls** | 2–4 specific, actionable items that would move the control to fully compliant |

**Deriving gaps without ServiceNow:** if no GRC data is connected, treat any threat where Existing
Compensating Controls is non-empty but the primary mitigation is not yet implemented as a compliance
gap candidate — the control partially works (compensating measures exist) but isn't complete (the
root-cause fix is still open).

## Common Failure Mode to Avoid

Writing the same generic recommendation ("improve monitoring," "conduct regular reviews") across
every gap. Every additional control listed must reference something specific and checkable — a named
field, a named credential, a named cadence (quarterly, per-deploy) — so a follow-up audit can verify
whether it was actually done.
