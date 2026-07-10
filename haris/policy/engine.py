"""Policy engine: resolves verdicts + policy into exactly one Decision.

Implements the four agreed rules:
  1. Threshold first  - a verdict scoring below its agent's threshold is
                        downgraded: BLOCK -> FLAG, anything else -> PASS.
                        A sub-threshold verdict's redacted_content is ignored.
  2. Most restrictive wins across surviving verdicts.
  3. Redaction composes sequentially, in agent order.
  4. Mode gates enforcement: in MONITOR the action is clamped to at most FLAG
     and `enforced` stays False. The Decision is always computed in full.

Default-deny (Policy.default_action) applies to relationship-rule lookup, which
is not implemented yet -- see TODO below.
"""
from __future__ import annotations

from haris.schemas.decision import Action, Decision, most_restrictive, rank
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict


def _verdict_action(v: Verdict, threshold: float) -> tuple[Action, bool]:
    """Map one verdict to an action. Returns (action, honor_redaction)."""
    if v.score < threshold:
        # Rule 1: sub-threshold. A block becomes a flag; everything else passes.
        return (Action.FLAG if v.label is Label.BLOCK else Action.ALLOW), False

    if v.label is Label.BLOCK:
        return Action.BLOCK, False
    if v.redacted_content is not None:
        return Action.REDACT, True
    if v.label is Label.FLAG:
        return Action.FLAG, False
    return Action.ALLOW, False


def resolve(message: Message, verdicts: list[Verdict], policy: Policy) -> Decision:
    actions: list[Action] = []
    reasons: list[str] = []
    content = message.content

    for v in verdicts:
        threshold = policy.thresholds.get(v.agent_name, 0.0)
        action, honor_redaction = _verdict_action(v, threshold)
        actions.append(action)
        if v.reason:
            reasons.append(f"{v.agent_name}: {v.reason}")
        # Rule 3: redactions compose in agent order, each on the previous result.
        if honor_redaction and v.redacted_content is not None:
            content = v.redacted_content

    # TODO(policy rules): match message against policy.rules on
    # (sender, receiver, data_type). If no rule permits the flow, fall back to
    # policy.default_action (default: BLOCK). Requires agents to report data_type.

    action = most_restrictive(actions)   # Rule 2

    # Rule 4: mode gate. Monitor never exceeds FLAG and never enforces.
    enforced = policy.mode is Mode.ENFORCE
    if not enforced and rank(action) > rank(Action.FLAG):
        action = Action.FLAG

    return Decision(
        action=action,
        final_content=content if action is Action.REDACT else None,
        verdicts=list(verdicts),
        reason="; ".join(reasons),
        enforced=enforced,
    )