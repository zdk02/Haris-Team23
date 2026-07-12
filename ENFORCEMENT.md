# Contract 6 — Decision / enforcement

Agents produce **Verdicts** (opinions about one message). The policy engine
resolves them into exactly one **Decision** (an outcome). The orchestrator acts
on the Decision.

`Verdict.label` has only `pass` / `flag` / `block`. An agent requests redaction
by setting `redacted_content` on its Verdict.

## Actions

Precedence, least to most restrictive:

    allow < log < flag < redact < block

- `allow` — deliver unchanged.
- `log` — deliver unchanged, record it.
- `flag` — deliver unchanged, record it, surface on the dashboard.
- `redact` — deliver `Decision.final_content` in place of the original.
- `block` — do not deliver.

## Resolution rules

1. **Threshold first.** A verdict whose `score` is below the threshold configured
   for its agent is downgraded: a `block` becomes a `flag`; anything else becomes
   `pass`. A sub-threshold verdict's `redacted_content` is ignored. Agents with no
   configured threshold default to `0.0` (always pass the gate).

2. **Most restrictive wins.** Map each surviving verdict to an action, then take
   the maximum along the precedence order. A single `block` beats any number of
   `pass`, and beats `redact`.

3. **Redaction composes in agent order.** When several agents supply
   `redacted_content`, apply them in the order the agents appear, each operating
   on the previous result. The final string becomes `Decision.final_content`.

4. **Mode gates enforcement, not decision.** The Decision is always computed in
   full. In `monitor` mode the action is clamped to at most `flag` and
   `Decision.enforced` is `False`. In `enforce` mode the action is applied and
   `enforced` is `True`. This is the guarantee that a false positive cannot break
   the app during development.

5. **No matching policy rule → deny.** `Policy.default_action` is `block`. Any
   flow not explicitly permitted by a `PolicyRule` is denied. (Rule matching on
   `(sender, receiver, data_type)` is not implemented yet — it needs agents to
   report `data_type`. The default is recorded now so the semantics are settled.)

## Returning a block to the sender

A blocked message has nothing to return. In `enforce` mode the orchestrator raises
`HarisBlocked(decision)`, which carries the Decision so the caller can log the
reason. The interception adapter lets it propagate to the sending agent. In
`monitor` mode nothing is ever raised.

## Effect on existing code

`Orchestrator.process()` returns a `Decision`, not a `Message`. The interception
adapter unwraps it into `(delivered_content, decision)` — or lets `HarisBlocked`
propagate. `Policy` gains a `default_action` field. The other five contracts are
unchanged.