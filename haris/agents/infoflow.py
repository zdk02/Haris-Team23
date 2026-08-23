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

Matching (Aug 22 rework, measured in report/evidence/):
  * Both sides are NORMALISED before comparison, so a double space or a reformatted
    identifier no longer defeats the check.
  * Matching is TOKEN-level with alphanumeric boundaries, so a tag is not matched
    inside a longer unrelated word.
  * The structured extractor only tags values from fields that actually identify
    somebody, so ordinary prose ("Status: stable") no longer taints the session.

Honest limit (measured in the Step 5 spike, see claude/Haris-Step5-Findings.md):
deep SEMANTIC paraphrase — the identifier itself reworded ("Type 2 diabetes" ->
"a chronic blood-sugar condition") — leaves no exact tag to resurface, so the coarse
detector passes it. That is the documented ceiling motivating the roadmap semantic
agent; `test_semantic_paraphrase_is_missed_the_ceiling` keeps it honest.
"""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from typing import Any, Iterable, Optional

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict

# Tokens too generic to be useful identifier tags. Clinical-flavoured because the demo
# is clinical — overridable per deployment via the `stopwords` constructor argument.
_STOPWORDS = frozenset({"patient", "record", "visit", "summary", "note", "follow", "up",
                        "the", "and", "of", "advised", "reports", "over"})

# Structured record fields whose VALUE identifies a person, a subject or a secret.
# Everything else in a "Key: value" record is prose and must not become taint.
# Overridable per deployment via the `identifying_keys` constructor argument — the
# agent stays application-agnostic; this frozenset is only the default.
_IDENTIFYING_KEYS = frozenset({
    "name", "mrn", "dob", "ssn", "diagnosis", "detail", "apikey",
    "stuid", "acct", "account", "empid", "email", "phone", "id", "recordid",
})

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> list[str]:
    """Lowercased alphanumeric words. Collapses runs of whitespace and punctuation, so
    'Robert  Roberts' and 'Robert Roberts' produce the same token list."""
    return _WORD.findall(s.lower())


def _norm_alnum(s: str) -> str:
    """Lowercase, letters and digits only — so 'MRN - 4821' and 'MRN 4 8 2 1' both
    collapse to the same string as 'MRN-4821'."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


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
        min_collapse_len: int = 6,
        identifying_keys: Iterable[str] = _IDENTIFYING_KEYS,
        stopwords: Iterable[str] = _STOPWORDS,
        tag_cache_size: int = 512,
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
        min_collapse_len: shortest normalised tag allowed to match with separators
            stripped. Below this length the collapsed form is too short to be evidence
            of anything ('DOB' would match inside 'dobbs'), so only token matching runs.
        identifying_keys: structured record fields whose value should become taint.
            Defaults to `_IDENTIFYING_KEYS`; pass your own for a non-clinical domain.
        stopwords: tokens too generic to be useful as identifier tags. Defaults to
        `_STOPWORDS`; pass your own for a non-clinical domain.
        tag_cache_size: how many extracted tag sets to remember, keyed by the source's
           content hash. The same PHI source is re-scanned on every hop of a session,
           so without this the NER pass runs once per hop instead of once per source.
           Set 0 to disable.
        """
        self.source_data_type = source_data_type
        self.min_tag_len = min_tag_len
        self._detector = detector
        self._detector_ready = detector is not _AUTO   # _AUTO builds lazily on first use
        self.internal_domains = tuple(d.lstrip("@").lower() for d in internal_domains)
        self.flag_unknown_destination = flag_unknown_destination
        self.use_structured_fallback = use_structured_fallback
        self.min_collapse_len = min_collapse_len
        # Normalise the keys once so lookup is insensitive to case, spaces and
        # punctuation ('Record ID', 'record_id' and 'recordid' all match).
        self.identifying_keys = frozenset(_norm_alnum(k) for k in identifying_keys)
        self.stopwords = frozenset(w.lower() for w in stopwords)
        # Bounded LRU: content hash -> extracted tags. Holds no more identifier data than
        # the state store already holds for the same session, is never persisted, and is
        # dropped with the agent. Races between threads can only cost a duplicate
        # extraction or a stale LRU order, never a wrong answer.
        self.tag_cache_size = tag_cache_size
        self._tag_cache: "OrderedDict[str, frozenset[str]]" = OrderedDict()

    # ------------------------------------------------------------------ #
    # SecurityAgent contract
    # ------------------------------------------------------------------ #

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        # A message that IS a PHI source is the ORIGIN, not a derived leak -- leave it
        # to the PII scanner / policy. Info-flow only judges DERIVED messages.
        #
        # But `data_type` is attacker-supplied, so this exemption must not be a way to
        # switch the agent off: a compromised sender would stamp data_type=PHI on its
        # exfiltration hop and skip the taint check entirely. Being a source explains why
        # a message HOLDS identifiers; it does not license sending them OUT. So the
        # exemption applies only while the hop stays inside the trust boundary. A
        # "source" bound for an external recipient is checked like any other message.
        if (message.metadata.get("data_type") == self.source_data_type
                and self._source_destination_permitted(message)):
            return self._pass("source PHI hop within the trust boundary; not a derived message")

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

        # Normalize the message ONCE, then test every tag against it. The old check was
        # `tag.lower() in content.lower()` — an exact substring match, which a double
        # space or a reformatted identifier defeated entirely.
        content_joined = " ".join(_tokens(message.content))
        content_alnum = _norm_alnum(message.content)
        hits = sorted({t for t in tags
                       if self._tag_resurfaces(t, content_joined, content_alnum)})
        if not hits:
            # Derived from PHI, but no source identifier resurfaced. This is the
            # coarse detector's blind spot for deep semantic paraphrase.
            return self._pass("derived from PHI but no source identifier resurfaced")

        # DESTINATION RULE — the info-flow judgment. Tainted PHI may reach an internal
        # recipient; heading outside the trust boundary is the violation.
        if self._destination_allowed(message):
            recipient = message.metadata.get("recipient")
            return self._pass(
                f"{len(hits)} derived identifier(s) resurfaced but destination is within "
                f"the trust boundary ({recipient}); PHI-origin flow permitted")

        redacted = self._mask(message.content, hits)
        recipient = message.metadata.get("recipient")
        # This reason reaches the SENDER via HarisBlocked (schemas/decision.py:62) and is
        # stored verbatim in the audit record. It must never carry the matched values: that
        # would tell a compromised sender exactly which strings tripped the detector so it
        # could bisect its payload, and it would put PHI into a log that holds only hashes.
        subj_note = f", {len(subjects)} data-subject(s)" if subjects else ""
        reason = (f"derived content carries {len(hits)} identifier(s) that originated in a "
                  f"PHI source and is bound outside the trust boundary "
                  f"(recipient={recipient}){subj_note}")
        score = min(0.99, 0.6 + 0.15 * len(hits))   # more identifiers -> higher score
        return Verdict(agent_name=self.name, label=Label.FLAG, score=score,
                       reason=reason, redacted_content=redacted)

    # ------------------------------------------------------------------ #
    # Matching
    # ------------------------------------------------------------------ #

    def _tag_resurfaces(self, tag: str, content_joined: str, content_alnum: str) -> bool:
        """Does `tag` reappear in the (already normalised) message?

        Two passes, in order of confidence:
          1. TOKEN match — the tag's words, in order, surrounded by spaces in the
             token-joined content. The padding spaces are what keep 'Ann' from
             matching inside 'Announcement'.
          2. COLLAPSED match — every non-alphanumeric character removed from both
             sides, so 'MRN - 0001' still matches 'MRN-0001'. Length-gated by
             `min_collapse_len`: a short collapsed tag is not evidence of anything.
        """
        tag_tokens = _tokens(tag)
        if not tag_tokens:
            return False
        if f" {' '.join(tag_tokens)} " in f" {content_joined} ":
            return True
        collapsed = _norm_alnum(tag)
        return len(collapsed) >= self.min_collapse_len and collapsed in content_alnum

    # ------------------------------------------------------------------ #
    # Destination rule
    # ------------------------------------------------------------------ #

    def _source_destination_permitted(self, message: Message) -> bool:
        """May a hop LABELLED as a PHI source claim the origin exemption?

        Only while it is not egressing. An absent recipient keeps the exemption, because
        an internal agent-to-agent handoff is exactly how a real source hop travels and
        absence cannot be distinguished from deletion (THREAT_MODEL.md, trusted metadata).
        A source bound for an EXTERNAL address gets no exemption - claiming to be an
        origin is not a licence to send identifiers outside.
        """
        recipient = message.metadata.get("recipient")
        if not recipient:
            return True
        return self._is_internal(str(recipient))

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
        """Tags for one PHI source, memoized by content hash. The orchestrator replays the
        whole session history on every hop, so an un-cached extractor re-runs the detector
        once per hop per source instead of once per source."""
        if self.tag_cache_size <= 0:
            return self._extract_tags_uncached(record_text)
        key = hashlib.sha256(record_text.encode("utf-8")).hexdigest()
        hit = self._tag_cache.get(key)
        if hit is not None:
            self._tag_cache.move_to_end(key)          # most recently used
            return set(hit)
        tags = frozenset(self._extract_tags_uncached(record_text))
        self._tag_cache[key] = tags
        if len(self._tag_cache) > self.tag_cache_size:
            self._tag_cache.popitem(last=False)       # evict least recently used
        return set(tags)

    def _extract_tags_uncached(self, record_text: str) -> set[str]:
        tags: set[str] = set()
        detector_tags = self._detector_tags(record_text)
        if detector_tags is not None:
            tags |= detector_tags

        # Union the structured extractor so record-specific identifiers the detector
        # doesn't model (MRN, free-text diagnosis) still taint. Also the sole source
        # of tags when the detector is unavailable.
        if self.use_structured_fallback or detector_tags is None:
            tags |= self._structured_tags(record_text)

        return {t for t in tags
                if len(t) >= self.min_tag_len and t.lower() not in self.stopwords}

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
        # structured "Key: value" lines -> take the values as identifier tags, but ONLY
        # for fields that actually identify somebody. Taking every value made ordinary
        # prose ("Status: stable") taint the session and produced false positives.
        for line in record_text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            if _norm_alnum(key) not in self.identifying_keys:
                continue
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
            toks = _tokens(h)
            if not toks:
                continue
            # Allow any run of non-alphanumerics between the tag's words, so a reformatted
            # identifier ('MRN - 0001') is redacted as well as an exact one ('MRN-0001').
            # The lookarounds are the redaction-side twin of the token match in
            # `_tag_resurfaces`: without them 'Ann' would redact inside 'Announcement'.
            pattern = (r"(?<![a-zA-Z0-9])"
                       + r"[^a-zA-Z0-9]*".join(re.escape(t) for t in toks)
                       + r"(?![a-zA-Z0-9])")
            out = re.sub(pattern, "[REDACTED]", out, flags=re.IGNORECASE)
        return out