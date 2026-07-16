"""Information-flow agent (Module 9) — promoted from the Step 5 spike.

Catches the *derived* leak (threat-model TC3): a message that contains no verbatim
copy of a record but still leaks identifying detail that ORIGINATED in a PHI source
earlier in the same session. A per-message regex / secrets scanner cannot see this,
because the summarizer rewrote the prose around the identifiers.

This agent sees it via LINEAGE, not string-matching-the-whole-record. It reads the
session history from `context`, pulls identifier "taint tags" off any PHI source that
flowed earlier in the session, and detects those tags resurfacing in the current
(derived) message. The tag travels with the data through Haris's state store, so it
survives the summarizer rewriting everything around it.

Phase 2 promotion over the spike (Module 9 scope):
  1. TAG SOURCE — the spike-grade structured `_extract_tags` is now backed by
     Module 7's real PII detector (`haris.agents.secrets_pii.PIIDetector`). The
     detector is INJECTABLE and lazy: if Presidio is unavailable we fall back to the
     structured extractor, and we UNION the two so we still tag record-specific
     identifiers Presidio doesn't model out of the box (MRN, free-text diagnosis).
  2. DESTINATION RULE — the spike flagged any resurfacing identifier regardless of
     where the message was going. Module 9 adds the actual information-*flow* judgment:
     tainted PHI is allowed to reach an INTERNAL recipient (inside the trust boundary)
     but not one outside it. This is distinct from Module 8's stateless relationship
     check — it is conditioned on the data's PHI *origin*.

Honest limit (measured in the Step 5 spike, see claude/Haris-Step5-Findings.md):
deep SEMANTIC paraphrase — the identifier itself reworded ("Type 2 diabetes" ->
"a chronic blood-sugar condition") — leaves no exact tag to resurface, so the coarse
detector passes it. That is the documented ceiling motivating the roadmap semantic
agent; `test_semantic_paraphrase_is_missed_the_ceiling` keeps it honest.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict

# Tokens too generic to be useful identifier tags.
_STOPWORDS = {"patient", "record", "visit", "summary", "note", "follow", "up",
              "the", "and", "of", "advised", "reports", "over"}

# Sentinel so we can tell "caller passed nothing (use the default Presidio detector)"
# apart from "caller passed None (disable the detector, structured tags only)".
_AUTO = object()


class InformationFlowAgent(SecurityAgent):
    name = "infoflow"

    def __init__(
        self,
        source_data_type: str = "PHI",
        min_tag_len: int = 4,
        *,
        detector: Any = _AUTO,
        internal_domains: Iterable[str] = ("hospital.internal",),
        flag_unknown_destination: bool = True,
        use_structured_fallback: bool = True,
    ) -> None:
        """
        detector: an object exposing `.analyze(text) -> results` where each result has
            `.start`, `.end`, `.entity_type`, `.score` (Presidio's RecognizerResult
            shape / Module 7's PIIDetector). Default `_AUTO` lazily builds a real
            PIIDetector; pass `None` to disable the detector (structured tags only);
            pass a custom object to inject your own (used in tests).
        internal_domains: recipient domains considered inside the trust boundary.
        flag_unknown_destination: when the message has no recipient in metadata, treat
            it as NOT allowed (flag). Keeps the spike's catch-by-default posture.
        use_structured_fallback: also union the structured record-field extractor so
            record-specific identifiers Presidio misses (MRN, diagnosis) still taint.
        """
        self.source_data_type = source_data_type
        self.min_tag_len = min_tag_len
        self._detector = detector
        self._detector_ready = detector is not _AUTO   # _AUTO builds lazily on first use
        self.internal_domains = tuple(d.lstrip("@").lower() for d in internal_domains)
        self.flag_unknown_destination = flag_unknown_destination
        self.use_structured_fallback = use_structured_fallback

    # ------------------------------------------------------------------ #
    # SecurityAgent contract
    # ------------------------------------------------------------------ #

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        # A message that IS a PHI source is the ORIGIN, not a derived leak -- leave it
        # to the PII scanner / policy. Info-flow only judges DERIVED messages.
        if message.metadata.get("data_type") == self.source_data_type:
            return self._pass("source PHI hop; not a derived message")

        # Collect taint tags (and subjects) from every PHI source seen earlier.
        tags: set[str] = set()
        subjects: set[str] = set()
        for m in context.get("history", []):
            if m is message:
                continue
            if m.metadata.get("data_type") == self.source_data_type:
                tags |= self._extract_tags(m.content)
                subject = m.metadata.get("data_subject")
                if subject:
                    subjects.add(str(subject))

        if not tags:
            return self._pass("no PHI source in lineage")

        haystack = message.content.lower()
        hits = sorted({t for t in tags if t.lower() in haystack})
        if not hits:
            # Derived from PHI, but no source identifier resurfaced. This is the
            # coarse detector's blind spot for deep semantic paraphrase.
            return self._pass("derived from PHI but no source identifier resurfaced")

        # DESTINATION RULE — the info-flow judgment. Tainted PHI may reach an internal
        # recipient; heading outside the trust boundary is the violation.
        if self._destination_allowed(message):
            recipient = message.metadata.get("recipient")
            return self._pass(
                f"derived identifiers {hits} resurfaced but destination is within "
                f"the trust boundary ({recipient}); PHI-origin flow permitted")

        redacted = self._mask(message.content, hits)
        subj_note = f" [data_subject(s): {sorted(subjects)}]" if subjects else ""
        recipient = message.metadata.get("recipient")
        reason = (f"derived content carries identifiers that originated in a PHI "
                  f"source and is bound outside the trust boundary "
                  f"(recipient={recipient}): {hits}{subj_note}")
        score = min(0.99, 0.6 + 0.15 * len(hits))   # more identifiers -> higher score
        return Verdict(agent_name=self.name, label=Label.FLAG, score=score,
                       reason=reason, redacted_content=redacted)

    # ------------------------------------------------------------------ #
    # Destination rule
    # ------------------------------------------------------------------ #

    def _destination_allowed(self, message: Message) -> bool:
        recipient = message.metadata.get("recipient")
        if not recipient:
            # No destination info: don't relax the spike's catch-by-default posture
            # unless explicitly configured to.
            return not self.flag_unknown_destination
        return self._is_internal(str(recipient))

    def _is_internal(self, recipient: str) -> bool:
        r = recipient.lower()
        return any(r.endswith("@" + d) or r.endswith("." + d) or r == d
                   for d in self.internal_domains)

    # ------------------------------------------------------------------ #
    # Tag extraction — Module 7 detector (primary) UNION structured (fallback)
    # ------------------------------------------------------------------ #

    def _extract_tags(self, record_text: str) -> set[str]:
        tags: set[str] = set()

        detector_tags = self._detector_tags(record_text)
        if detector_tags is not None:
            tags |= detector_tags

        # Union the structured extractor so record-specific identifiers the detector
        # doesn't model (MRN, free-text diagnosis) still taint. Also the sole source
        # of tags when the detector is unavailable.
        if self.use_structured_fallback or detector_tags is None:
            tags |= self._structured_tags(record_text)

        return {t for t in tags if len(t) >= self.min_tag_len and t.lower() not in _STOPWORDS}

    def _detector_tags(self, text: str) -> Optional[set[str]]:
        """Tags from Module 7's PIIDetector. Returns None if no detector is available
        (import/engine failure or explicitly disabled), so the caller can fall back."""
        detector = self._get_detector()
        if detector is None:
            return None
        try:
            results = detector.analyze(text)
        except Exception:
            # Presidio/spaCy not installed, model missing, etc. Degrade gracefully.
            return None
        tags: set[str] = set()
        for r in results:
            try:
                value = text[r.start:r.end].strip()
            except (AttributeError, TypeError):
                continue
            if value:
                tags.add(value)
        return tags

    def _get_detector(self) -> Any:
        if self._detector is None:
            return None
        if self._detector is _AUTO:
            # Lazily build Module 7's PIIDetector; if that import fails, disable it.
            try:
                from haris.agents.secrets_pii import PIIDetector
                self._detector = PIIDetector()
            except Exception:
                self._detector = None
                return None
        return self._detector

    def _structured_tags(self, record_text: str) -> set[str]:
        """Spike-grade structured extractor: bracketed subject id + 'Key: value' lines.
        Kept as a fallback / union partner to the real detector."""
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
                if part:
                    tags.add(part)
        return tags

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)

    def _mask(self, text: str, hits: list[str]) -> str:
        out = text
        for h in sorted(hits, key=len, reverse=True):   # longest first, avoid partials
            out = re.sub(re.escape(h), "[REDACTED]", out, flags=re.IGNORECASE)
        return out