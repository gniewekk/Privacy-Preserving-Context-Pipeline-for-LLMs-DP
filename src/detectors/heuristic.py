"""Heuristic gazetteer detector and ContextRuleEnhancer for lowercase, inflected, and split PII."""

from __future__ import annotations

import re
from collections.abc import Sequence

from detectors.base import PIIDetector, register_detector, resolve_overlapping_spans
from domain.models import DataClass, DetectedEntity, EntityType

# Bilingual gazetteer of common English & Polish given names (base + inflected stems)
_GIVEN_NAMES: frozenset[str] = frozenset(
    {
        # English
        "john",
        "james",
        "robert",
        "michael",
        "william",
        "david",
        "richard",
        "joseph",
        "thomas",
        "charles",
        "mary",
        "patricia",
        "jennifer",
        "linda",
        "elizabeth",
        "barbara",
        "susan",
        "jessica",
        "sarah",
        "karen",
        "alice",
        "bob",
        "emma",
        "oliver",
        "charlotte",
        # Polish (nominative + common inflected forms: narzędnik/dopełniacz/celownik)
        "jan",
        "jana",
        "janem",
        "janowi",
        "piotr",
        "piotra",
        "piotrem",
        "anna",
        "anny",
        "anną",
        "annie",
        "maria",
        "marii",
        "marią",
        "katarzyna",
        "katarzyny",
        "katarzyną",
        "paweł",
        "pawła",
        "pawłem",
        "michał",
        "michała",
        "michałem",
        "tomasz",
        "tomasza",
        "tomaszem",
        "krzysztof",
        "krzysztofa",
        "krzysztofem",
        "agnieszka",
        "agnieszki",
        "agnieszką",
    }
)

_SURNAME_PATTERNS: frozenset[str] = frozenset(
    {
        # English
        "smith",
        "johnson",
        "williams",
        "brown",
        "jones",
        "garcia",
        "miller",
        "davis",
        "wilson",
        "anderson",
        "taylor",
        "thomas",
        "moore",
        "jackson",
        "martin",
        "doe",
        # Polish (nominative + inflected forms)
        "kowalski",
        "kowalskiego",
        "kowalskim",
        "kowalska",
        "kowalskiej",
        "kowalską",
        "nowak",
        "nowaka",
        "nowakiem",
        "wiśniewski",
        "wiśniewskiego",
        "wiśniewskim",
        "wisniewski",
        "wisniewskiego",
        "wisniewskim",
        "wójcik",
        "wójcika",
        "wojcik",
        "kamiński",
        "kamińskiego",
        "kaminski",
        "lewandowski",
        "lewandowskiego",
        "lewandowskim",
        "zieliński",
        "zielińskiego",
        "zielinski",
    }
)

_CONTEXT_PERSON_TRIGGERS = re.compile(
    r"\b(?:patient|client|user|customer|mr\.?|mrs\.?|ms\.?|dr\.?|prof\.?|"
    r"my name is|named|contacted by|"
    r"pacjent|pacjentka|klient|klientka|pan|pani| z panem| z panią|"
    r"nazywam się|nazywa się|mgr|lek\.?|dr)\b",
    re.IGNORECASE,
)

_CONTEXT_ADDRESS_PATTERN = re.compile(
    r"\b(?:ul\.|ulica|al\.|aleja|os\.|plac)\s+[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż0-9.\-]+"
    r"(?:\s+\d+[A-Za-z]?(?:/\d+)?)?\b|"
    r"\b\d{1,5}[A-Za-z]?\s+[A-Za-z]+\s+(?:street|st\.|avenue|ave\.|road|rd\.|boulevard|blvd\.)\b",
    re.IGNORECASE,
)

# Abbreviated initial + surname (e.g. "j. kowalski", "J. Smith") and two-token name pairs
_INITIAL_AND_SURNAME_PATTERN = re.compile(
    r"\b([A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż])\.\s*([A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]{3,25})\b"
)
_TWO_WORD_CANDIDATE_PATTERN = re.compile(
    r"\b([A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]{2,20})\s+([A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]{2,25})\b"
)


def _looks_like_polish_surname(word_lower: str) -> bool:
    if word_lower in _SURNAME_PATTERNS:
        return True
    return word_lower.endswith(
        ("ski", "skiego", "skiemu", "skim", "ska", "skiej", "ską", "cki", "ckiego", "ckim", "cka")
    )


class ContextRuleEnhancer:
    """Context-window enhancer that boosts confidence of lowercase/inflected NER detections."""

    def __init__(
        self,
        context_window_chars: int = 40,
        trigger_boost: float = 0.25,
        gazetteer_boost: float = 0.20,
        min_accepted_confidence: float = 0.55,
    ) -> None:
        self._context_window_chars = context_window_chars
        self._trigger_boost = trigger_boost
        self._gazetteer_boost = gazetteer_boost
        self._min_accepted_confidence = min_accepted_confidence

    def enhance(
        self,
        text: str,
        entities: Sequence[DetectedEntity],
    ) -> tuple[DetectedEntity, ...]:
        """Boost confidence of entities supported by context keywords or gazetteer entries."""
        enhanced: list[DetectedEntity] = []
        for entity in entities:
            boost = 0.0
            window_start = max(0, entity.start - self._context_window_chars)
            left_context = text[window_start : entity.start]

            if _CONTEXT_PERSON_TRIGGERS.search(left_context):
                boost += self._trigger_boost

            tokens = [t.lower().strip(".") for t in entity.raw_value.split() if t]
            if any(t in _GIVEN_NAMES or _looks_like_polish_surname(t) for t in tokens):
                boost += self._gazetteer_boost

            new_confidence = min(1.0, entity.confidence + boost)
            if new_confidence >= self._min_accepted_confidence:
                if boost > 0.0:
                    enhanced.append(
                        entity.model_copy(update={"confidence": round(new_confidence, 4)})
                    )
                else:
                    enhanced.append(entity)

        return resolve_overlapping_spans(enhanced)


@register_detector("heuristic")
class HeuristicPIIDetector(PIIDetector):
    """Context-keyword and gazetteer heuristic detector for lowercase, inflected, and split PII."""

    def __init__(self, context_window_chars: int = 40) -> None:
        self._context_window_chars = context_window_chars

    @property
    def detector_id(self) -> str:
        return "heuristic_pii_detector"

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        """Detect lowercase/inflected names, abbreviated names, and street addresses."""
        detected: list[DetectedEntity] = []

        # 1. Abbreviated initial + surname (e.g. "j. kowalski", "j. smith")
        for match in _INITIAL_AND_SURNAME_PATTERN.finditer(text):
            surname_lower = match.group(2).lower()
            window_start = max(0, match.start() - self._context_window_chars)
            has_trigger = bool(_CONTEXT_PERSON_TRIGGERS.search(text[window_start : match.start()]))
            if _looks_like_polish_surname(surname_lower) or has_trigger:
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.PERSON,
                        start=match.start(),
                        end=match.end(),
                        raw_value=match.group(0),
                        confidence=0.88 if has_trigger else 0.80,
                        data_class=DataClass.CONFIDENTIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 2. Two-word given-name + surname pairs (works on all-lowercase & Polish inflected forms)
        for match in _TWO_WORD_CANDIDATE_PATTERN.finditer(text):
            first_lower = match.group(1).lower()
            second_lower = match.group(2).lower()
            is_known_first = first_lower in _GIVEN_NAMES
            is_known_surname = _looks_like_polish_surname(second_lower)
            window_start = max(0, match.start() - self._context_window_chars)
            has_trigger = bool(_CONTEXT_PERSON_TRIGGERS.search(text[window_start : match.start()]))

            if (is_known_first and is_known_surname) or (is_known_first and has_trigger):
                base_conf = 0.65 if match.group(0).islower() else 0.82
                conf = min(1.0, base_conf + (0.20 if has_trigger else 0.15))
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.PERSON,
                        start=match.start(),
                        end=match.end(),
                        raw_value=match.group(0),
                        confidence=conf,
                        data_class=DataClass.CONFIDENTIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 3. Street addresses ("ul. lipowa 5", "221b baker street")
        for match in _CONTEXT_ADDRESS_PATTERN.finditer(text):
            detected.append(
                DetectedEntity(
                    entity_type=EntityType.LOCATION,
                    start=match.start(),
                    end=match.end(),
                    raw_value=match.group(0),
                    confidence=0.85,
                    data_class=DataClass.CONFIDENTIAL,
                    detector_id=self.detector_id,
                )
            )

        return resolve_overlapping_spans(detected)
