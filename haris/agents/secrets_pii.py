"""SecretsPIIAgent — Module 7 (Secrets & PII detection via Presidio + detect-secrets).

A stateless SecurityAgent. For each message it scans the content for PII
(Presidio) and credentials/keys (detect-secrets) and reports what it found.
Integration, not invention: no custom regexes or entity models live here —
both detectors are the off-the-shelf libraries, wrapped behind two small
helpers that Module 9 (Information-flow) can reuse directly:

  * ``PIIDetector``     — Presidio analyzer + anonymizer. ``analyze()`` returns
    scored entity spans; ``redact()`` masks them (``Jane Doe`` -> ``<PERSON>``).
    This is the drop-in replacement for the info-flow spike's ``_extract_tags``.
  * ``SecretsDetector`` — a fixed set of detect-secrets *plugins*, instantiated
    directly. (The library's ``transient_settings``/``scan_line`` path ignores
    entropy limits in v1.5.0 and flags common English words, so we call the
    precise regex/keyword plugins ourselves; the plugin list is constructor
    config, so entropy plugins can be opted into per deployment.)

Severity mapping (the part that makes the policy engine's thresholds behave):
Presidio happily reports DATE_TIME for phrases like "follow up in two weeks",
which would false-positive every clean summary (TC1). So each entity type
carries a *weight*; a finding's severity is ``detector_score * weight`` and the
verdict's ``score`` is the max severity across findings. Weak entities
(DATE_TIME, LOCATION) only matter in the company of strong ones (PERSON,
EMAIL_ADDRESS, ...), which alone clear the flag threshold.

Verdict semantics:
  * nothing above the flag threshold        -> PASS  (score = computed severity)
  * PII and/or secrets above the threshold  -> FLAG, ``redacted_content`` set to
    the message content with every detected span masked.

The agent never emits BLOCK and contains no monitor/enforce logic: a FLAG
carrying ``redacted_content`` is exactly what the policy engine resolves to a
REDACT in enforce mode and clamps to a flag in monitor mode (the same channel
the info-flow spike uses). ``redacted_content`` is deliberately *not* set on a
PASS — the engine treats any above-threshold verdict with redacted content as
a redaction request.

Nothing hospital-specific is hardcoded; entity types, weights, thresholds,
plugins, and the spaCy model are constructor arguments with sensible defaults.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict


# --------------------------------------------------------------------------- #
# Defaults (override in constructors for another deployment)                   #
# --------------------------------------------------------------------------- #

# Presidio entity types scanned by default. Chosen for a records-handling app:
# identity, contact, government/financial identifiers, plus dates & locations
# as weak corroborating signals.
DEFAULT_ENTITIES: tuple[str, ...] = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "MEDICAL_LICENSE",
    "US_DRIVER_LICENSE",
    "DATE_TIME",
    "LOCATION",
)

# Entity weight = how identifying the entity is on its own. A finding's
# severity is presidio_score * weight. Anything not listed weighs 1.0.
DEFAULT_ENTITY_WEIGHTS: Mapping[str, float] = {
    "DATE_TIME": 0.3,   # "in two weeks", "today" — noise unless paired
    "LOCATION": 0.6,
}

DEFAULT_FLAG_THRESHOLD = 0.5   # min severity for the agent to flag
DEFAULT_PII_MIN_SCORE = 0.4    # drop Presidio findings below this raw score
DEFAULT_SECRET_SCORE = 0.9     # regex/keyword plugin hits are near-certain
DEFAULT_SECRET_MASK = "<SECRET>"
DEFAULT_SPACY_MODEL = "en_core_web_sm"
DEFAULT_LANGUAGE = "en"


@dataclass(frozen=True)
class Finding:
    """One detected item, from either detector, in a common shape."""
    kind: str          # "pii" | "secret"
    entity_type: str   # e.g. "PERSON" or "AWS Access Key"
    severity: float    # weighted 0-1 score used for thresholding
    value: Optional[str] = None  # the matched secret text (secrets only)


# --------------------------------------------------------------------------- #
# PIIDetector — reusable Presidio wrapper (Module 9 imports this)              #
# --------------------------------------------------------------------------- #

class PIIDetector:
    """Thin wrapper over Presidio's AnalyzerEngine + AnonymizerEngine.

    Lazy-initialised: Presidio loads a spaCy pipeline, which is slow and
    needs the model installed, so nothing heavy happens until first use.
    """

    def __init__(
        self,
        entities: Iterable[str] = DEFAULT_ENTITIES,
        min_score: float = DEFAULT_PII_MIN_SCORE,
        spacy_model: str = DEFAULT_SPACY_MODEL,
        language: str = DEFAULT_LANGUAGE,
    ) -> None:
        self.entities = list(entities)
        self.min_score = min_score
        self.spacy_model = spacy_model
        self.language = language
        self._analyzer = None
        self._anonymizer = None

    # -- lazy engines ------------------------------------------------------ #

    def _ensure_engines(self) -> None:
        if self._analyzer is not None:
            return
        import logging as _logging
        # Presidio logs a WARNING for every predefined recognizer whose language it skips
        # (es/it/pl while we run en) and for unmapped spaCy labels (CARDINAL). That is
        # cosmetic noise -- quiet it so demo/CLI output is readable. Real errors still surface.
        _logging.getLogger("presidio-analyzer").setLevel(_logging.ERROR)
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": self.language, "model_name": self.spacy_model}],
        })
        self._analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
        self._anonymizer = AnonymizerEngine()

    # -- API ---------------------------------------------------------------- #

    def analyze(self, text: str):
        """Return Presidio RecognizerResults (entity, span, score) above min_score."""
        self._ensure_engines()
        results = self._analyzer.analyze(
            text=text, entities=self.entities, language=self.language)
        return [r for r in results if r.score >= self.min_score]

    def redact(self, text: str, results=None) -> str:
        """Mask detected spans: 'Jane Doe' -> '<PERSON>'. Reuses `results` if given."""
        self._ensure_engines()
        if results is None:
            results = self.analyze(text)
        if not results:
            return text
        return self._anonymizer.anonymize(text=text, analyzer_results=results).text


# --------------------------------------------------------------------------- #
# SecretsDetector — detect-secrets plugin wrapper                              #
# --------------------------------------------------------------------------- #

def _default_secret_plugins() -> list:
    """Precise (regex/keyword) detect-secrets plugins; no entropy noise."""
    from detect_secrets.plugins.aws import AWSKeyDetector
    from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
    from detect_secrets.plugins.basic_auth import BasicAuthDetector
    from detect_secrets.plugins.github_token import GitHubTokenDetector
    from detect_secrets.plugins.jwt import JwtTokenDetector
    from detect_secrets.plugins.keyword import KeywordDetector
    from detect_secrets.plugins.private_key import PrivateKeyDetector
    from detect_secrets.plugins.slack import SlackDetector
    from detect_secrets.plugins.stripe import StripeDetector

    return [
        AWSKeyDetector(),
        AzureStorageKeyDetector(),
        BasicAuthDetector(),
        GitHubTokenDetector(),
        JwtTokenDetector(),
        KeywordDetector(),
        PrivateKeyDetector(),
        SlackDetector(),
        StripeDetector(),
    ]


class SecretsDetector:
    """Runs detect-secrets plugins line-by-line over free text."""

    def __init__(self, plugins: Optional[Sequence] = None) -> None:
        self._plugins = list(plugins) if plugins is not None else None  # lazy

    def _ensure_plugins(self) -> list:
        if self._plugins is None:
            self._plugins = _default_secret_plugins()
        return self._plugins

    def scan(self, text: str) -> list[tuple[str, str]]:
        """Return deduped (secret_type, secret_value) pairs found in `text`."""
        found: set[tuple[str, str]] = set()
        for plugin in self._ensure_plugins():
            for line in text.splitlines() or [text]:
                for hit in plugin.analyze_string(line):
                    if hit:  # analyze_string yields the matched secret string
                        found.add((plugin.secret_type, str(hit)))
        return sorted(found)

    @staticmethod
    def redact(text: str, findings: Iterable[tuple[str, str]],
               mask: str = DEFAULT_SECRET_MASK) -> str:
        """Replace every detected secret value with `mask` (longest first, so a
        short match can't corrupt a longer secret it is a substring of)."""
        for _type, value in sorted(findings, key=lambda f: -len(f[1])):
            if value:
                text = text.replace(value, mask)
        return text


# --------------------------------------------------------------------------- #
# The agent                                                                    #
# --------------------------------------------------------------------------- #

class SecretsPIIAgent(SecurityAgent):
    name = "secrets_pii"

    def __init__(
        self,
        pii_detector: Optional[PIIDetector] = None,
        secrets_detector: Optional[SecretsDetector] = None,
        entity_weights: Mapping[str, float] = DEFAULT_ENTITY_WEIGHTS,
        flag_threshold: float = DEFAULT_FLAG_THRESHOLD,
        secret_score: float = DEFAULT_SECRET_SCORE,
        secret_mask: str = DEFAULT_SECRET_MASK,
        *,
        internal_domains: Iterable[str] = ("hospital.internal",),
        redact_on_egress_only: bool = True,
        treat_missing_recipient_as_internal: bool = True,
        always_redact_secrets: bool = False,
    ) -> None:
        self.pii = pii_detector or PIIDetector()
        self.secrets = secrets_detector or SecretsDetector()
        self.entity_weights = dict(entity_weights)
        self.flag_threshold = flag_threshold
        self.secret_score = secret_score
        self.secret_mask = secret_mask
        # Boundary-awareness (mirrors AuthorizationAgent / InformationFlowAgent):
        #   redact_on_egress_only=True  -> DETECT everywhere (always logged for the audit
        #     trail), but only rewrite content (-> REDACT) when the message is leaving the
        #     trust boundary. On a safe internal hop the finding is FLAGged and the content
        #     is delivered UNCHANGED, so PII a downstream agent legitimately needs (e.g. the
        #     patient's name to the treating doctor) is not scrubbed and never mangled.
        #   redact_on_egress_only=False -> the original destination-agnostic behavior:
        #     redact wherever anything is detected.
        #   always_redact_secrets=True  -> credential exception: even on an internal hop,
        #     mask hard secrets (keys/tokens) while still letting PII through.
        self.internal_domains = tuple(d.lstrip("@").lower() for d in internal_domains)
        self.redact_on_egress_only = redact_on_egress_only
        self.treat_missing_recipient_as_internal = treat_missing_recipient_as_internal
        self.always_redact_secrets = always_redact_secrets

    # -- SecurityAgent ------------------------------------------------------ #

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        text = message.content or ""

        pii_results = self.pii.analyze(text) if text else []
        secret_hits = self.secrets.scan(text) if text else []
        findings = self._to_findings(pii_results, secret_hits)

        severity = max((f.severity for f in findings), default=0.0)
        if severity < self.flag_threshold:
            return self._pass(severity, findings)

        # Boundary decision: rewrite content only when leaving the trust boundary
        # (or when not configured to gate on egress at all).
        enforce_here = (not self.redact_on_egress_only) or self._is_egress(message)

        if enforce_here:
            redacted = self.pii.redact(text, pii_results) if pii_results else text
            if secret_hits:
                redacted = SecretsDetector.redact(redacted, secret_hits, self.secret_mask)
            return Verdict(
                agent_name=self.name,
                label=Label.FLAG,
                score=severity,
                reason=self._describe(findings) + " (egress → redacting)",
                redacted_content=redacted,
            )

        # Safe internal hop: log the finding, deliver unchanged. Optionally still mask
        # hard secrets (never PII) so a credential can't be forwarded even internally.
        if self.always_redact_secrets and secret_hits:
            redacted = SecretsDetector.redact(text, secret_hits, self.secret_mask)
            return Verdict(
                agent_name=self.name,
                label=Label.FLAG,
                score=severity,
                reason=self._describe(findings) + " (internal hop → secrets masked, PII logged)",
                redacted_content=redacted,
            )

        return Verdict(
            agent_name=self.name,
            label=Label.FLAG,
            score=severity,
            reason=self._describe(findings) + " (internal hop → logged, delivered unchanged)",
        )

    # -- boundary helpers --------------------------------------------------- #

    def _is_egress(self, message: Message) -> bool:
        """True if this hop delivers to a recipient outside the trust boundary."""
        recipient = (message.metadata or {}).get("recipient")
        if not recipient:
            # No recipient = an internal agent-to-agent handoff, not an external send.
            return not self.treat_missing_recipient_as_internal
        return not self._is_internal(str(recipient))

    def _is_internal(self, recipient: str) -> bool:
        r = recipient.lower()
        return any(r.endswith("@" + d) or r.endswith("." + d) or r == d
                   for d in self.internal_domains)

    # -- helpers ------------------------------------------------------------ #

    def _to_findings(self, pii_results, secret_hits) -> list[Finding]:
        out = [
            Finding(kind="pii", entity_type=r.entity_type,
                    severity=r.score * self.entity_weights.get(r.entity_type, 1.0))
            for r in pii_results
        ]
        out += [
            Finding(kind="secret", entity_type=stype,
                    severity=self.secret_score, value=value)
            for stype, value in secret_hits
        ]
        return out

    @staticmethod
    def _describe(findings: list[Finding]) -> str:
        pii = sorted({f.entity_type for f in findings if f.kind == "pii"})
        sec = sorted({f.entity_type for f in findings if f.kind == "secret"})
        parts = []
        if pii:
            parts.append("PII: " + ", ".join(pii))
        if sec:
            parts.append("secrets: " + ", ".join(sec))
        return "detected " + "; ".join(parts)

    def _pass(self, severity: float, findings: list[Finding]) -> Verdict:
        why = ("no PII or secrets detected" if not findings else
               f"only weak signals below threshold ({self._describe(findings)})")
        # NOTE: no redacted_content on a PASS — the engine would read an
        # above-threshold verdict carrying redacted content as a redact request.
        return Verdict(agent_name=self.name, label=Label.PASS,
                       score=severity, reason=why)
