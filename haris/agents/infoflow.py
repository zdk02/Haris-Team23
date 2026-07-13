"""Information-flow agent (Step 5 spike -> first real cut).

Catches the *derived* leak (threat-model TC3): a message that contains no verbatim
copy of a record but still leaks identifying detail that ORIGINATED in a PHI source
earlier in the same session. A per-message regex / secrets scanner cannot see this,
because the summarizer rewrote the prose around the identifiers.

This agent sees it via LINEAGE, not string-matching-the-whole-record. It reads the
session history from `context`, pulls identifier "taint tags" off any PHI source
that flowed earlier in the session, and detects those tags resurfacing in the
current (derived) message. The tag travels with the data through Haris's memory, so
it survives the summarizer rewriting everything around it.

This is COARSE, token-level propagation tagging. Honest limits (measured in the Step
5 spike, see claude/Haris-Step5-Findings.md):
  * It catches surface paraphrase (prose around an identifier rewritten).      [OK]
  * It MISSES deep semantic paraphrase (the identifier itself reworded, e.g.
    "Type 2 diabetes" -> "a chronic blood-sugar condition").          [false negative]
  * Generic identifiers (a common diagnosis word) can over-flag.       [false positive]
The semantic ceiling is what motivates the roadmap semantic agent. In production the
`_extract_tags` heuristic below is replaced by a real PII detector (Presidio); the
lineage logic is unchanged.
"""
from __future__ import annotations

import re
from typing import Any

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict

# Tokens too generic to be useful identifier tags.
_STOPWORDS = {"patient", "record", "visit", "summary", "note", "follow", "up",
              "the", "and", "of", "advised", "reports", "over"}


class InformationFlowAgent(SecurityAgent):
    name = "infoflow"

    def __init__(self, source_data_type: str = "PHI", min_tag_len: int = 4) -> None:
        self.source_data_type = source_data_type
        self.min_tag_len = min_tag_len

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        # A message that IS a PHI source is the ORIGIN, not a derived leak -- leave it
        # to the PII scanner / policy. Info-flow only judges DERIVED messages.
        if message.metadata.get("data_type") == self.source_data_type:
            return self._pass("source PHI hop; not a derived message")

        # Collect taint tags from every PHI source seen earlier in this session.
        tags: set[str] = set()
        for m in context.get("history", []):
            if m is message:
                continue
            if m.metadata.get("data_type") == self.source_data_type:
                tags |= self._extract_tags(m.content)

        if not tags:
            return self._pass("no PHI source in lineage")

        haystack = message.content.lower()
        hits = sorted({t for t in tags if t.lower() in haystack})
        if not hits:
            # Derived from PHI, but no source identifier resurfaced. This is the
            # coarse detector's blind spot for deep semantic paraphrase.
            return self._pass("derived from PHI but no source identifier resurfaced")

        redacted = self._mask(message.content, hits)
        reason = ("derived content carries identifiers that originated in a PHI "
                  f"source: {hits}")
        score = min(0.99, 0.6 + 0.15 * len(hits))   # more identifiers -> higher score
        return Verdict(agent_name=self.name, label=Label.FLAG, score=score,
                       reason=reason, redacted_content=redacted)

    # -- helpers (spike-grade; a real PII detector replaces _extract_tags) --------
    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)

    def _extract_tags(self, record_text: str) -> set[str]:
        tags: set[str] = set()
        # subject id from a header like "PATIENT RECORD [patient-A]"
        for m in re.findall(r"\[([^\]]+)\]", record_text):
            tags.add(m.strip())
        # structured "Key: value" lines -> take the values as identifier tags
        for line in record_text.splitlines():
            if ":" not in line:
                continue
            _, _, value = line.partition(":")
            for part in re.split(r"[;,]", value):   # split "a; b, c" compounds
                part = part.strip()
                if len(part) >= self.min_tag_len and part.lower() not in _STOPWORDS:
                    tags.add(part)
        return tags

    def _mask(self, text: str, hits: list[str]) -> str:
        out = text
        for h in sorted(hits, key=len, reverse=True):   # longest first, avoid partials
            out = re.sub(re.escape(h), "[REDACTED]", out, flags=re.IGNORECASE)
        return out