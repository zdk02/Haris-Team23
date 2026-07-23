"""Policy engine: resolves verdicts + policy into exactly one Decision.

Implements the four agreed rules:
  1. Threshold first  - a verdict scoring below its agent's threshold is
                        downgraded: BLOCK -> FLAG, anything else -> PASS.
                        A sub-threshold verdict's redacted_content is ignored.
  2. Most restrictive wins across surviving verdicts.
  3. Redaction composes sequentially, in agent order.
  4. Mode gates enforcement: in MONITOR the action is clamped to at most FLAG
     and `enforced` stays False. The Decision is always computed in full.
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Optional
from haris.schemas.decision import Action, Decision, most_restrictive, rank
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict

# Helpers
def _masked_spans(original: str, redacted: str, min_keep: int = 3) -> list[tuple[int, int]]:
    # Recover, as (start, end) ranges in `original`, the spans this agent rewrote --
    # by diffing its full rewrite against the original. Short unchanged runs (< min_keep
    # chars) sitting *between* two changed regions are absorbed into the mask, so a
    # character shared by chance (e.g. the 'S' in 'John Smith' vs '<PERSON>') can't
    # fragment one identifier into '[REDACTED]S[REDACTED]'. Over-masking slightly is
    # safe; fragmenting an identifier is not.
    spans: list[tuple[int, int]] = []
    cur: Optional[tuple[int, int]] = None
    for tag, i1, i2, _j1, _j2 in SequenceMatcher(a=original, b=redacted, autojunk=False).get_opcodes():
        if tag == "equal":
            if (i2 - i1) >= min_keep:
                if cur is not None:
                    spans.append(cur)
                    cur = None
            elif cur is not None:
                cur = (cur[0], i2)          # absorb a short unchanged run into the open mask
        elif i2 > i1:                        # replace / delete (pure insertions have i1 == i2)
            cur = (i1, i2) if cur is None else (cur[0], i2)
    if cur is not None:
        spans.append(cur)
    return spans

def _verdict_action(v: Verdict, threshold: float) -> tuple[Action, bool]:
    # Rule 1: threshold first.
    # A below-threshold BLOCK becomes FLAG.
    # Any other below-threshold verdict becomes ALLOW.
    # Below-threshold redacted_content is ignored.

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

def _get_actions(verdicts: list[Verdict], policy: Policy) -> list[tuple[Verdict, Action, bool]]:
    """
    Apply thresholds to all verdicts.

    Each returned tuple contains: verdict, resulting action, honor_redaction
    """
    actions: list[tuple[Verdict, Action, bool]] = []

    for verdict in verdicts:
        # Rule 1: apply each agent's configured threshold.
        # Missing thresholds default to 0.0.

        threshold = policy.thresholds.get(verdict.agent_name, 0.0)

        action, honor_redaction = _verdict_action(verdict, threshold)

        actions.append((verdict, action, honor_redaction))

    return actions


def _select_action(actions: list[tuple[Verdict, Action, bool]]) -> Action:
    # Rule 2: most restrictive action wins.
    # Precedence: ALLOW < LOG < FLAG < REDACT < BLOCK.

    action_values = [action for _, action, _ in actions]

    return most_restrictive(action_values)


def _compose_redactions(original_content: str, actions: list[tuple[Verdict, Action, bool]]) -> str:
    # Rule 3: redactions compose. Union every honored agent's masked spans (in ORIGINAL
    # coordinates), merge overlapping/adjacent ranges, and rebuild the content once with
    # a standardized [REDACTED] token. Working in span coordinates -- rather than
    # str.replace on recovered substrings -- means no agent's mask is lost and a literal
    # '[REDACTED]' one agent already emitted can't be re-matched by another (Module 10:
    # union masks, don't let the last writer win).
    spans: list[tuple[int, int]] = []
    for verdict, _, honor_redaction in actions:
        if honor_redaction and verdict.redacted_content is not None:
            spans.extend(_masked_spans(original_content, verdict.redacted_content))

    if not spans:
        return original_content

    spans.sort()
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    out: list[str] = []
    prev = 0
    for start, end in merged:
        out.append(original_content[prev:start])
        out.append("[REDACTED]")
        prev = end
    out.append(original_content[prev:])
    return "".join(out)

def _apply_mode(recommended_action: Action, mode: Mode) -> tuple[Action, bool]:
    # Rule 4: mode gates enforcement.

    # ENFORCE keeps the selected action.
    if mode is Mode.ENFORCE:
        return recommended_action, True

    # MONITOR never redacts or block: REDACT and BLOCK are clamped to FLAG.
    if rank(recommended_action) > rank(Action.FLAG):
        return Action.FLAG, False

    return recommended_action, False

def _build_reason(actions: list[tuple[Verdict, Action, bool]]) -> str:
    reasons: list[str] = []

    for verdict, _, _ in actions:
        if verdict.reason:
            reasons.append(
                f"{verdict.agent_name}: {verdict.reason}"
            )

    return "; ".join(reasons)

# Message resolution
def resolve(message: Message, verdicts: list[Verdict], policy: Policy) -> Decision:
    """Resolve all agent verdicts into one final Decision."""
    # Rule 1: threshold every verdict and convert it into an action.
    actions = _get_actions(verdicts, policy)

    # Rule 2: choose the most restrictive surviving action.
    action = _select_action(actions)

    # Rule 3: prepare the redacted content in agent order.
    content = _compose_redactions(message.content, actions)

    # Rule 4: apply monitor or enforce mode.
    effective_action, enforced = _apply_mode(action, policy.mode)

    return Decision(
        action=effective_action,
        final_content=(content if effective_action is Action.REDACT else None),
        verdicts=list(verdicts),
        reason=_build_reason(actions),
        enforced=enforced)